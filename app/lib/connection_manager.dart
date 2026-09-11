/// Connect-all manager: keeps one TLS link per roster computer and aggregates
/// their pending/decision streams into a single view for the approval screen.
///
/// Reconnect policy per computer: on every (re)connect, re-discover the
/// computer via mDNS first and pin the advertised fingerprint; only when that
/// fails does it fall back to the stored `lastAddr`. The old socket is closed
/// before dialing so a stale IP never collides with the daemon's per-IP
/// connection limit. Links are keyed (and deduped) by pinned fingerprint so
/// mDNS and `lastAddr` pointing at the same machine never open two sockets.
library;

import 'dart:async';

import 'daemon_client.dart';
import 'key_store.dart';
import 'tcp_tls_link.dart';

class ConnectionManager {
  ConnectionManager({
    required this.keyStore,
    required this.identity,
    DaemonClient Function(RosterComputer computer)? clientFactory,
    Future<List<TcpComputer>> Function()? browse,
  })  : _clientFactory = clientFactory ??
            ((computer) => DaemonClient(
                  pubkey: identity.publicKeyBase64,
                  source: computer.fingerprint,
                  sourceName: computer.name,
                )),
        _browse = browse ?? TcpTlsLink.browse;

  static const Duration _initialBackoff = Duration(seconds: 1);
  static const Duration _maxBackoff = Duration(seconds: 30);

  final KeyStore keyStore;
  final DeviceIdentity identity;
  final DaemonClient Function(RosterComputer computer) _clientFactory;
  final Future<List<TcpComputer>> Function() _browse;

  final Map<String, _ComputerLink> _links = <String, _ComputerLink>{};

  final StreamController<PendingSession> _pending =
      StreamController<PendingSession>.broadcast();
  final StreamController<DecisionResult> _decisions =
      StreamController<DecisionResult>.broadcast();
  final StreamController<String> _unregistered =
      StreamController<String>.broadcast();

  /// Aggregated pending requests from every computer, each tagged with its
  /// source computer (fingerprint + name).
  Stream<PendingSession> pending() => _pending.stream;

  /// Aggregated decision results from every computer, each tagged with its
  /// source computer.
  Stream<DecisionResult> decisions() => _decisions.stream;

  /// Emits the fingerprint of a roster computer whose link answered
  /// `welcome{registered:false}` — it no longer recognizes this phone's key.
  Stream<String> unregistered() => _unregistered.stream;

  /// Opens a link to every roster computer and starts the connect loops.
  Future<void> start() async {
    final roster = await keyStore.roster();
    for (final computer in roster) {
      final fp = computer.fingerprint;
      if (_links.containsKey(fp)) continue; // dedupe by pinned fingerprint
      final client = _clientFactory(computer);
      final link = _ComputerLink(computer, client);
      _links[fp] = link;
      link.pendingSub = client.pending().listen(_pending.add);
      link.decisionsSub = client.decisions().listen(_decisions.add);
      link.connectionSub = client.connection().listen((bool connected) {
        if (connected) return;
        // A drop during our own (re)connect is expected (the old socket was
        // closed first); only an unsolicited drop arms a reconnect.
        if (link.connecting || link.stopped) return;
        _scheduleRetry(link);
      });
      unawaited(_connect(link));
    }
  }

  Future<void> _connect(_ComputerLink link) async {
    if (link.stopped) return;
    link.connecting = true;
    try {
      Welcome? welcome;
      TcpComputer? discovered;

      // Dial the cached lastAddr first: it is fast and usually still valid, so
      // a fresh launch or resume is not gated on a slow mDNS browse (which
      // would otherwise drop the first sudo request pushed right after).
      final parsed = _parseLastAddr(link.computer.lastAddr);
      if (parsed != null) {
        try {
          welcome = await link.client.connect(
            host: parsed.$1,
            port: parsed.$2,
            fp: link.computer.fingerprint,
          );
        } catch (_) {
          welcome = null; // stale or unreachable; fall through to mDNS.
        }
      }

      // lastAddr failed (or absent): discover via mDNS and pin by fingerprint.
      if (welcome == null) {
        try {
          for (final c in await _browse()) {
            if (c.fp.toLowerCase() ==
                link.computer.fingerprint.toLowerCase()) {
              discovered = c;
              break;
            }
          }
        } catch (_) {
          // mDNS unavailable this pass.
        }
        if (discovered == null) {
          _scheduleRetry(link);
          return;
        }
        welcome = await link.client.connect(
          host: discovered.host,
          port: discovered.port,
          fp: link.computer.fingerprint,
        );
      }
      link.backoff = _initialBackoff;

      if (!welcome.registered) {
        // The computer dropped this key (re-paired to another phone): surface
        // it and stop this link; the approval screen prompts re-pairing.
        if (!link.stopped) _unregistered.add(link.computer.fingerprint);
        await _stop(link);
        return;
      }

      // Refresh lastAddr when mDNS moved the computer.
      if (discovered != null &&
          discovered.lastAddr != link.computer.lastAddr) {
        link.computer = RosterComputer(
          name: link.computer.name,
          fingerprint: link.computer.fingerprint,
          lastAddr: discovered.lastAddr,
        );
        await keyStore.addComputer(
          name: link.computer.name,
          fingerprint: link.computer.fingerprint,
          lastAddr: discovered.lastAddr,
        );
      }
    } catch (_) {
      _scheduleRetry(link);
    } finally {
      link.connecting = false;
    }
  }

  void _scheduleRetry(_ComputerLink link) {
    if (link.stopped || link.retryTimer != null) return;
    final delay = link.backoff;
    link.backoff = _boundedBackoff(link.backoff * 2);
    link.retryTimer = Timer(delay, () {
      link.retryTimer = null;
      unawaited(_connect(link));
    });
  }

  static Duration _boundedBackoff(Duration d) =>
      d > _maxBackoff ? _maxBackoff : d;

  /// Routes a signed decision to the owning computer's link (matched by the
  /// session's source fingerprint).
  Future<DecisionResult> postDecision({
    required PendingSession session,
    required String decision,
    required String signatureBase64,
  }) async {
    final source = session.source;
    final link = source == null ? null : _links[source];
    if (link == null) {
      throw StateError('No active link for session ${session.id}');
    }
    return link.client.postDecision(
      sessionId: session.id,
      decision: decision,
      signatureBase64: signatureBase64,
    );
  }

  /// Whether a roster computer is currently registered (i.e. its link
  /// answered `welcome{registered:true}`), for the "approved by X" check.
  String? welcomeKeyFor(String fingerprint) =>
      _links[fingerprint]?.client.welcomeKey;

  /// Stops and removes one computer (keep the device key; forget only this
  /// computer).
  Future<void> forgetComputer(String fingerprint) async {
    final link = _links.remove(fingerprint);
    if (link != null) await _stop(link);
    await keyStore.removeComputer(fingerprint);
  }

  Future<void> _stop(_ComputerLink link) async {
    if (link.stopped) return;
    link.stopped = true;
    link.retryTimer?.cancel();
    link.retryTimer = null;
    await link.pendingSub?.cancel();
    await link.decisionsSub?.cancel();
    await link.connectionSub?.cancel();
    await link.client.dispose();
  }

  Future<void> dispose() async {
    for (final link in _links.values.toList()) {
      await _stop(link);
    }
    _links.clear();
    await _pending.close();
    await _decisions.close();
    await _unregistered.close();
  }

  static (String, int)? _parseLastAddr(String addr) {
    final i = addr.lastIndexOf(':');
    if (i <= 0 || i == addr.length - 1) return null;
    final host = addr.substring(0, i);
    final port = int.tryParse(addr.substring(i + 1));
    if (host.isEmpty || port == null) return null;
    return (host, port);
  }
}

class _ComputerLink {
  _ComputerLink(this.computer, this.client);

  RosterComputer computer;
  final DaemonClient client;

  bool stopped = false;
  bool connecting = false;
  Duration backoff = ConnectionManager._initialBackoff;
  Timer? retryTimer;
  StreamSubscription<PendingSession>? pendingSub;
  StreamSubscription<DecisionResult>? decisionsSub;
  StreamSubscription<bool>? connectionSub;
}
