/// Framed TCP+TLS client for one phone-fprint-auth daemon computer.
///
/// Wire protocol (see daemon/frame.go): every frame is a 4-byte big-endian
/// length prefix followed by UTF-8 JSON (see frame.dart). On connect the phone
/// sends `hello{pubkey,name[,token]}`; the daemon answers `welcome{registered,
/// key,pending[]}` (or `registered{key}` on the pairing path), then pushes
/// `pending{...}` frames and broadcasts `decision-result{...}` frames. The
/// phone answers `decision{id,decision,sig}` and keeps the link alive with
/// `ping` every ~15s.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'frame.dart';
import 'tcp_tls_link.dart';

/// A pending sudo/pkexec approval request pushed by the daemon.
class PendingSession {
  PendingSession({
    required this.id,
    required this.nonce,
    required this.user,
    required this.service,
    required this.tty,
    this.reason = '',
    this.command = '',
    required this.expiresAt,
    this.source,
    this.sourceName,
  });

  /// Parses a daemon→phone `pending` frame
  /// (`{"type":"pending","id":...,"nonce":...,"user":...,"service":...,
  /// "tty":...,"reason":...,"command":...,"expires_at":...}`).
  factory PendingSession.fromFrameJson(
    Map<String, dynamic> json, {
    String? source,
    String? sourceName,
  }) =>
      PendingSession(
        id: json['id'] as String,
        // nonce is base64 (std, padded) of 32 raw bytes.
        nonce: base64.decode(json['nonce'] as String),
        user: json['user'] as String? ?? '',
        service: json['service'] as String? ?? '',
        tty: json['tty'] as String? ?? '',
        reason: json['reason'] as String? ?? '',
        command: json['command'] as String? ?? '',
        expiresAt: _unixSeconds(json['expires_at']),
        source: source,
        sourceName: sourceName,
      );

  final String id;
  final Uint8List nonce;
  final String user;
  final String service;
  final String tty;

  /// Agent-supplied justification (untrusted, self-reported); '' when the
  /// daemon omitted it.
  final String reason;

  /// The objective command line the daemon captured; '' when omitted.
  final String command;

  /// Absolute deadline, from the daemon's `expires_at` (unix seconds).
  final DateTime expiresAt;

  /// Which roster computer pushed this (its TLS fingerprint), or null when
  /// untagged (e.g. parsed outside a [DaemonClient]).
  final String? source;

  /// The source computer's display name (mirrors [source]).
  final String? sourceName;

  /// Plain-JSON form for the cross-engine bridge (service engine → UI engine
  /// and UI → service decision RPC); [nonce] travels as base64.
  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': id,
        'nonce': base64.encode(nonce),
        'user': user,
        'service': service,
        'tty': tty,
        'reason': reason,
        'command': command,
        'expiresAt': expiresAt.millisecondsSinceEpoch,
        'source': source,
        'sourceName': sourceName,
      };

  /// Inverse of [toJson]; used by the UI engine to replay bridged sessions.
  factory PendingSession.fromJson(Map<String, dynamic> json) => PendingSession(
        id: json['id'] as String,
        nonce: base64.decode(json['nonce'] as String),
        user: json['user'] as String? ?? '',
        service: json['service'] as String? ?? '',
        tty: json['tty'] as String? ?? '',
        reason: json['reason'] as String? ?? '',
        command: json['command'] as String? ?? '',
        expiresAt:
            DateTime.fromMillisecondsSinceEpoch(json['expiresAt'] as int),
        source: json['source'] as String?,
        sourceName: json['sourceName'] as String?,
      );

  static DateTime _unixSeconds(dynamic v) {
    if (v is int) return DateTime.fromMillisecondsSinceEpoch(v * 1000);
    if (v is num) return DateTime.fromMillisecondsSinceEpoch((v * 1000).round());
    return DateTime.now();
  }
}

/// The daemon's answer to a posted decision. On success [status] is
/// `approved`, `denied` or `expired` (and [key] names the paired key that
/// signed it, empty for `expired`); on failure [error] carries the reason
/// (e.g. `invalid-signature`, `unknown-session`, `not-pending`).
class DecisionResult {
  const DecisionResult({this.id, this.status, this.key, this.error, this.source});

  factory DecisionResult.fromFrameJson(
    Map<String, dynamic> json, {
    String? source,
  }) =>
      DecisionResult(
        id: json['id'] as String? ?? '',
        status: json['status'] as String?,
        key: json['key'] as String?,
        error: json['error'] as String?,
        source: source,
      );

  final String? id;
  final String? status;
  final String? key;
  final String? error;

  /// Which roster computer this result came from (its TLS fingerprint).
  final String? source;

  /// Plain-JSON form for the cross-engine bridge.
  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': id,
        'status': status,
        'key': key,
        'error': error,
        'source': source,
      };

  /// Inverse of [toJson].
  factory DecisionResult.fromJson(Map<String, dynamic> json) => DecisionResult(
        id: json['id'] as String?,
        status: json['status'] as String?,
        key: json['key'] as String?,
        error: json['error'] as String?,
        source: json['source'] as String?,
      );

  /// True when the daemon rejected the decision.
  bool get isError => error != null;

  /// True when the session expired before any decision landed.
  bool get isExpired => status == 'expired';
}

/// The control frame answering [DaemonClient.connect]: whether the pubkey is
/// registered on that computer, under which key name, plus the snapshot of
/// currently pending sessions.
class Welcome {
  const Welcome({
    required this.registered,
    required this.key,
    required this.pending,
  });

  final bool registered;
  final String? key;
  final List<PendingSession> pending;
}

/// Framed client for a single daemon computer: performs the hello handshake,
/// streams pending requests (deduped by id) and decision results, and posts
/// signed decisions. Decisions still awaiting their result survive a
/// reconnect and are re-posted idempotently (the daemon's `decide` returns
/// the original verdict for a repeated id).
class DaemonClient {
  DaemonClient({
    TcpTlsLink? link,
    required this.pubkey,
    this.phoneName = 'phone',
    this.source,
    this.sourceName,
  }) : _link = link ?? TcpTlsLink() {
    _sub = _link.events.listen(_onEvent);
  }

  /// How long [postDecision] waits for the matching `decision-result` frame.
  static const Duration decisionTimeout = Duration(seconds: 15);

  /// How long [connect] waits for the `welcome`/`registered` control frame.
  static const Duration helloTimeout = Duration(seconds: 10);

  /// How often the keepalive `ping` is sent (the daemon idles out at ~30s).
  static const Duration pingInterval = Duration(seconds: 15);

  final TcpTlsLink _link;

  /// This phone's padded base64 Ed25519 public key (the hello identity).
  final String pubkey;

  /// Display name sent in hello (unused by the daemon for identity).
  final String phoneName;

  /// Roster tags stamped onto every pending/decision-result this client emits.
  final String? source;
  final String? sourceName;

  final FrameDecoder _decoder = FrameDecoder();
  final StreamController<Map<String, dynamic>> _decoded =
      StreamController<Map<String, dynamic>>.broadcast();
  final StreamController<PendingSession> _pending =
      StreamController<PendingSession>.broadcast();
  final Set<String> _pendingIds = <String>{};

  /// Decisions sent but not yet answered, keyed by session id. Retained
  /// across reconnect so [connect] can re-post them idempotently.
  final Map<String, _InFlightDecision> _inFlight = <String, _InFlightDecision>{};

  StreamSubscription<TcpEvent>? _sub;
  Timer? _pingTimer;

  bool _registered = false;
  String? _welcomeKey;

  /// Whether the current link is registered on its computer.
  bool get registered => _registered;

  /// This phone's key name on the current computer (from `welcome.key`), or
  /// null when not registered. Used to tell our own decision-results apart
  /// from another phone's ("approved by X").
  String? get welcomeKey => _welcomeKey;

  void _onEvent(TcpEvent event) {
    if (event.status == 'connected') {
      _decoder.reset();
      return;
    }
    if (event.status != 'data' || event.data == null) return;
    List<Uint8List> frames;
    try {
      frames = _decoder.add(event.data!);
    } on FrameTooLargeException {
      _decoder.reset();
      return; // Malformed/oversized frame; drop and resume at a fresh frame.
    }
    for (final frame in frames) {
      final json = _decodeFrameJson(frame);
      if (json == null) continue;
      _decoded.add(json);
      _dispatch(json);
    }
  }

  void _dispatch(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'pending':
        final session = PendingSession.fromFrameJson(
          json,
          source: source,
          sourceName: sourceName,
        );
        if (_pendingIds.add(session.id)) _pending.add(session);
      case 'pong':
        break;
    }
  }

  /// Connects to the daemon at [host]:[port] (pinning the leaf cert to [fp]),
  /// performs the hello handshake and returns the resulting [Welcome]. A
  /// [token] puts the link on the pairing path (the daemon consumes it and
  /// answers `registered{key}`). Any old socket is closed first. Re-posts
  /// in-flight decisions so their verdicts survive the reconnect.
  Future<Welcome> connect({
    required String host,
    required int port,
    required String fp,
    String? token,
  }) async {
    _pingTimer?.cancel();
    await _disconnect(); // close the old socket before dialing a new one
    await _link.connect(host, port, fp);
    _registered = false;
    _welcomeKey = null;

    // Subscribe to the control frame before sending hello so the reply can
    // never be missed.
    final welcomeFuture = _decoded.stream
        .map(_parseWelcome)
        .firstWhere((w) => w != null)
        .then((w) => w!);

    final hello = <String, dynamic>{
      'type': 'hello',
      'pubkey': pubkey,
      'name': phoneName,
      if (token != null && token.isNotEmpty) 'token': token,
    };
    await _sendJson(hello);

    final welcome = await welcomeFuture.timeout(helloTimeout);
    _registered = welcome.registered;
    _welcomeKey = welcome.key;

    // Snapshot pending sessions first (deduped), then re-post any decisions
    // that were in flight when the link dropped.
    for (final session in welcome.pending) {
      if (_pendingIds.add(session.id)) _pending.add(session);
    }
    for (final entry in _inFlight.values.toList()) {
      await _sendRaw(entry.frameJson);
    }

    if (_registered) _startPing();
    return welcome;
  }

  void _startPing() {
    _pingTimer?.cancel();
    _pingTimer = Timer.periodic(pingInterval, (_) {
      unawaited(_sendJson(const <String, dynamic>{'type': 'ping'}));
    });
  }

  /// The stream of pending approval requests pushed by the daemon (welcome
  /// snapshot + live pushes), deduped by session id and tagged with the
  /// source computer.
  Stream<PendingSession> pending() => _pending.stream;

  /// The stream of every `decision-result` frame this link receives (our own
  /// decisions and other phones'), each tagged with the source computer.
  Stream<DecisionResult> decisions() => _decoded.stream
      .where((json) => json['type'] == 'decision-result')
      .map((json) => DecisionResult.fromFrameJson(json, source: source));

  /// The link's transport state: yields true on `connected`, false on
  /// `disconnected`/`error`. The [ConnectionManager] uses the false edges to
  /// schedule a reconnect.
  Stream<bool> connection() => _link.events
      .map((TcpEvent e) => e.status)
      .where((String? s) =>
          s == 'connected' || s == 'disconnected' || s == 'error')
      .map((String? s) => s == 'connected');

  /// Sends a signed `decision` frame and awaits the matching `decision-result`
  /// frame (matched by session id). The decision is retained in-flight on
  /// timeout/disconnect so a later reconnect re-posts it idempotently.
  Future<DecisionResult> postDecision({
    required String sessionId,
    required String decision,
    required String signatureBase64,
  }) async {
    final frameJson = json.encode(<String, dynamic>{
      'type': 'decision',
      'id': sessionId,
      'decision': decision,
      'sig': signatureBase64,
    });
    final inFlight = _InFlightDecision(sessionId, frameJson);
    _inFlight[sessionId] = inFlight;

    final sub = decisions().listen((result) {
      if (result.id == sessionId && !inFlight.completer.isCompleted) {
        _inFlight.remove(sessionId);
        inFlight.completer.complete(result);
      }
    });

    try {
      await _sendRaw(frameJson);
      return await inFlight.completer.future.timeout(decisionTimeout);
    } catch (_) {
      // Keep the decision in-flight; a reconnect re-posts it. The caller
      // (ConnectionManager) observes the failure and triggers the reconnect.
      rethrow;
    } finally {
      await sub.cancel();
    }
  }

  /// Closes the underlying socket. In-flight decisions are retained so a
  /// later [connect] re-posts them.
  Future<void> dispose() async {
    _pingTimer?.cancel();
    _pingTimer = null;
    await _sub?.cancel();
    _sub = null;
    await _disconnect();
    await _decoded.close();
    await _pending.close();
  }

  Future<void> _disconnect() => _link.disconnect();

  Future<void> _sendJson(Map<String, dynamic> map) =>
      _sendRaw(json.encode(map));

  Future<void> _sendRaw(String jsonString) async {
    await _link.send(encodeFrame(Uint8List.fromList(utf8.encode(jsonString))));
  }

  Welcome? _parseWelcome(Map<String, dynamic> json) {
    if (json['type'] == 'welcome') {
      final rawPending = json['pending'] as List<dynamic>? ?? const [];
      final pending = rawPending
          .map((dynamic e) => PendingSession.fromFrameJson(
                e as Map<String, dynamic>,
                source: source,
                sourceName: sourceName,
              ))
          .toList();
      return Welcome(
        registered: json['registered'] == true,
        key: json['key'] as String?,
        pending: pending,
      );
    }
    if (json['type'] == 'registered') {
      return Welcome(
        registered: true,
        key: json['key'] as String?,
        pending: const [],
      );
    }
    return null;
  }

  static Map<String, dynamic>? _decodeFrameJson(Uint8List frame) {
    final Object? decoded;
    try {
      decoded = json.decode(utf8.decode(frame));
    } on FormatException {
      return null;
    }
    if (decoded is! Map<String, dynamic>) return null;
    return decoded;
  }
}

class _InFlightDecision {
  _InFlightDecision(this.id, this.frameJson);

  final String id;
  final String frameJson;
  final Completer<DecisionResult> completer = Completer<DecisionResult>();
}
