/// Cross-engine bridge between the headless background engine (inside
/// `ApprovalForegroundService`) and the Activity's UI engine.
///
/// SINGLE OWNERSHIP: the daemon sockets live in the service engine only —
/// its Dart isolate runs the real [ConnectionManager] and is the single
/// frame consumer. The UI engine never dials for approvals. The two isolates
/// talk over `dart:ui` [IsolateNameServer] ports, which the engine registers
/// process-wide (natives, so it works across the two engines in one process):
///
///   - `phonefprint.service`: registered by the service isolate
///     ([BackgroundLinkService]); receives RPC requests from the UI.
///   - `phonefprint.ui`: registered by the UI isolate while an approval
///     screen is alive; receives pushed events (pending / decision-result /
///     unregistered) and RPC replies.
///
/// The UI still performs a direct TLS dial for QR pairing; that traffic is
/// delegated at the channel level to the same process-wide [TcpTlsChannel]
/// (see `TcpTlsChannelDelegate.kt`), so even pairing sockets are owned by
/// the service engine.
library;

import 'dart:async';
import 'dart:isolate';
import 'dart:ui' as ui;

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import 'app_theme.dart';
import 'connection_manager.dart';
import 'daemon_client.dart';
import 'format.dart';
import 'key_store.dart';
import 'overlay_channel.dart';

/// Well-known port names for the cross-engine bridge. These must match the
/// documentation above; they are process-local and never leave the device.
const String kServicePortName = 'phonefprint.service';
const String kUiPortName = 'phonefprint.ui';

/// Entry point of the background link owner (the headless engine's isolate).
/// Called from the `mainBackground()` Dart entrypoint that
/// `ApprovalForegroundService` executes.
Future<void> startBackgroundService() async {
  WidgetsFlutterBinding.ensureInitialized();
  final service = BackgroundLinkService();
  await service.run();
}

/// The service engine's side of the bridge: runs the real [ConnectionManager],
/// subscribes to its streams and forwards events to the UI isolate, and
/// answers RPC requests (postDecision / forget / snapshot) from the UI.
class BackgroundLinkService {
  final ReceivePort _port = ReceivePort();

  /// High-priority approval-request notifier (native [ApprovalNotifier],
  /// channel `com.phonefprint.auth/notify`). Only the service engine
  /// registers that handler, so this channel is usable from this isolate
  /// only — the UI engine's pending path never touches it.
  static const MethodChannel _notifyChannel =
      MethodChannel('com.phonefprint.auth/notify');

  ConnectionManager? _manager;
  KeyStore? _keyStore;
  DeviceIdentity? _identity;

  /// Most recent pending sessions, replayed to the UI on attach so a request
  /// pushed while the UI was dead is not lost. Keyed by session id; pruned
  /// on decision-result and on expiry.
  final Map<String, PendingSession> _pendingCache = <String, PendingSession>{};
  static const int _pendingCacheLimit = 100;

  Future<void> run() async {
    // Re-register in case a previous engine in this process left a stale name.
    ui.IsolateNameServer.removePortNameMapping(kServicePortName);
    ui.IsolateNameServer.registerPortWithName(_port.sendPort, kServicePortName);
    _port.listen(_onMessage);
    // Overlay button events (deny / expired). APPROVE never arrives here:
    // the overlay launches the main Activity for the biometric flow.
    OverlayChannel.decisions().listen(_onOverlayEvent);
    await _bootstrap();
  }

  /// Loads the shared identity and starts the link owner. Retries: the
  /// entrypoint starts before the engine's plugins are attached on a cold
  /// start, so the first secure-storage reads can miss the channel; and the
  /// identity does not exist until the UI has generated it once.
  Future<void> _bootstrap() async {
    final keyStore = KeyStore();
    DeviceIdentity? identity;
    while (identity == null) {
      try {
        identity = await keyStore.load();
      } catch (e) {
        debugPrint('phone-fprint-auth: bg identity load failed: $e');
      }
      if (identity == null) {
        await Future<void>.delayed(const Duration(seconds: 5));
      }
    }
    _keyStore = keyStore;
    _identity = identity;
    final manager = ConnectionManager(keyStore: keyStore, identity: identity);
    _manager = manager;
    manager.pending().listen(_onPending);
    manager.decisions().listen(_onDecision);
    manager.unregistered().listen(_onUnregistered);
    while (true) {
      try {
        await manager.start();
        return;
      } catch (e) {
        debugPrint('phone-fprint-auth: bg link start failed: $e');
        await Future<void>.delayed(const Duration(seconds: 5));
      }
    }
  }

  void _onPending(PendingSession session) {
    final key = '${session.id}@${session.source ?? ''}';
    if (_pendingCache.length >= _pendingCacheLimit) {
      _pendingCache.remove(_pendingCache.keys.first);
    }
    _pendingCache[key] = session;
    _pruneExpired();
    final json = session.toJson();
    // The registered UI port doubles as the foreground signal: attached
    // means the approval screen (in-app card + SystemSound, task 7) is
    // alive and owns the alert; unattached means the app is backgrounded
    // or killed and the alert must come from the service engine itself.
    final deliveredToUi =
        _sendToUi(<String, dynamic>{'type': 'pending', 'session': json});
    if (!deliveredToUi) {
      unawaited(_alertInBackground(json));
    }
  }

  void _onDecision(DecisionResult result) {
    if (result.id != null) {
      _pendingCache.remove('${result.id}@${result.source ?? ''}');
    }
    final source = result.source;
    _sendToUi(<String, dynamic>{
      'type': 'decision',
      'result': result.toJson(),
      'myKey': source == null ? null : _manager?.welcomeKeyFor(source),
    });
  }

  void _onUnregistered(String fingerprint) {
    _sendToUi(
        <String, dynamic>{'type': 'unregistered', 'fingerprint': fingerprint});
  }

  /// Overlay button events from the native overlay window. Only `expired`
  /// and a DENY decision arrive here: APPROVE launches the main Activity
  /// instead (task 12). A deny needs no biometric, but it must still be
  /// SIGNED — this isolate signs it with the shared identity and posts it
  /// through the single signed-decision path (never bypassing it).
  void _onOverlayEvent(Map<String, dynamic> event) {
    final type = event['type'] as String?;
    final id = event['id'] as String?;
    if (id == null) return;
    if (type == 'expired') {
      _pendingCache.removeWhere((key, _) => key.startsWith('$id@'));
      return;
    }
    if (type != 'decision' || event['decision'] != 'deny') return;
    unawaited(_signAndPostDeny(id, event['source'] as String?));
  }

  Future<void> _signAndPostDeny(String id, String? source) async {
    final manager = _manager;
    final identity = _identity;
    if (manager == null || identity == null) return;
    final session = _sessionById(id, source);
    if (session == null) return; // already decided or expired; nothing to sign.
    try {
      final sig = await signDecision(
        keyPair: identity.keyPair,
        action: kActionDeny,
        user: session.user,
        service: session.service,
        tty: session.tty,
        nonce: session.nonce,
      );
      final result = await manager.postDecision(
        session: session,
        decision: kActionDeny,
        signatureBase64: sig,
      );
      debugPrint('phone-fprint-auth: overlay deny for ${session.id}: '
          '${result.status ?? result.error}');
    } catch (e) {
      debugPrint('phone-fprint-auth: overlay deny failed: $e');
    }
  }

  /// The cached session for an overlay event: exact `id@source` first (the
  /// event carries the source), then any computer with that id.
  PendingSession? _sessionById(String id, String? source) {
    final keyed = _pendingCache['$id@$source'];
    if (keyed != null) return keyed;
    for (final entry in _pendingCache.entries) {
      if (entry.key.startsWith('$id@')) return entry.value;
    }
    return null;
  }

  void _pruneExpired() {
    final now = DateTime.now();
    _pendingCache.removeWhere((_, s) => s.expiresAt.isBefore(now));
  }

  /// Sends [message] to the UI isolate and reports whether the UI port was
  /// registered (the "is the app foregrounded" signal used by [_onPending]).
  bool _sendToUi(Map<String, dynamic> message) {
    final port = ui.IsolateNameServer.lookupPortByName(kUiPortName);
    if (port == null) return false;
    port.send(message);
    return true;
  }

  /// Background-only alert for a pending request that could not reach the
  /// UI isolate: shows the native overlay card AND posts a high-priority
  /// notification (silent when the user disabled the approval sound). The
  /// foreground path never gets here because the UI port is registered.
  /// Both calls are fire-and-forget from [_onPending] and must not throw.
  Future<void> _alertInBackground(Map<String, dynamic> json) async {
    // Resolve the overlay palette from the app theme at runtime (task 18):
    // the native card derives its colors from the very scheme the app runs,
    // so it can never drift from the design language.
    final overlay = OverlayChannel
        .show(<String, dynamic>{...json, 'palette': overlayPalette()})
        .catchError((Object e) {
      debugPrint('phone-fprint-auth: bg overlay show failed: $e');
      return '';
    });
    var soundEnabled = true;
    try {
      soundEnabled =
          await (_keyStore?.loadSoundEnabled() ?? Future<bool>.value(true));
    } catch (e) {
      debugPrint('phone-fprint-auth: bg sound pref load failed: $e');
    }
    try {
      await _notifyChannel.invokeMethod<void>('showApproval', <String, dynamic>{
        ...json,
        'sound': soundEnabled,
      });
    } on MissingPluginException catch (e) {
      debugPrint('phone-fprint-auth: bg notify handler missing: $e');
    } on PlatformException catch (e) {
      debugPrint('phone-fprint-auth: bg notify failed: $e');
    }
    await overlay;
  }

  void _onMessage(dynamic raw) {
    if (raw is! Map || raw['type'] != 'request') return;
    unawaited(_handleRequest(raw));
  }

  Future<void> _handleRequest(Map<dynamic, dynamic> raw) async {
    final id = raw['id'] as int?;
    final replyTo = raw['replyTo'] as SendPort?;
    final method = raw['method'] as String?;
    final args = raw['args'];
    final argMap = args is Map
        ? Map<String, dynamic>.from(args)
        : <String, dynamic>{};

    void reply(dynamic value) => replyTo
        ?.send(<String, dynamic>{'type': 'reply', 'id': id, 'value': value});
    void replyError(Object error) => replyTo
        ?.send(<String, dynamic>{'type': 'reply', 'id': id, 'error': '$error'});

    final manager = _manager;
    if (manager == null) {
      replyError('background link not ready');
      return;
    }
    try {
      switch (method) {
        case 'start':
          await manager.start();
          reply(null);
        case 'snapshot':
          _pruneExpired();
          reply(_pendingCache.values.map((s) => s.toJson()).toList());
        case 'welcomeKeys':
          final keys = <String, String?>{};
          for (final c in await _keyStore!.roster()) {
            keys[c.fingerprint] = manager.welcomeKeyFor(c.fingerprint);
          }
          reply(keys);
        case 'postDecision':
          final session = PendingSession.fromJson(
              Map<String, dynamic>.from(argMap['session'] as Map));
          final result = await manager.postDecision(
            session: session,
            decision: argMap['decision'] as String,
            signatureBase64: argMap['sig'] as String,
          );
          reply(result.toJson());
        case 'forgetComputer':
          await manager.forgetComputer(argMap['fingerprint'] as String);
          reply(null);
        case 'hideOverlay':
          await OverlayChannel.hide();
          reply(null);
        default:
          replyError('unknown method: $method');
      }
    } catch (e) {
      replyError(e);
    }
  }
}

/// The UI engine's side of the bridge: consumes the service's pushed events,
/// exposes them as streams, and issues RPC requests. Backed by
/// [ServiceLinkManager] so [ApprovalScreen] keeps its [ConnectionManager]
/// surface unchanged.
class UiBridge {
  ReceivePort? _port;
  final StreamController<PendingSession> _pending =
      StreamController<PendingSession>.broadcast();
  final StreamController<DecisionResult> _decisions =
      StreamController<DecisionResult>.broadcast();
  final StreamController<String> _unregistered =
      StreamController<String>.broadcast();
  final Map<String, String> _welcomeKeys = <String, String>{};
  final Map<int, Completer<Map<dynamic, dynamic>>> _inflight =
      <int, Completer<Map<dynamic, dynamic>>>{};

  int _nextRequestId = 0;
  bool _attached = false;

  Stream<PendingSession> get pendingStream => _pending.stream;
  Stream<DecisionResult> get decisionsStream => _decisions.stream;
  Stream<String> get unregisteredStream => _unregistered.stream;

  /// Registers the UI port, replays the snapshot of currently pending
  /// sessions, refreshes the welcome-key cache and asks the service to
  /// (re)connect every roster computer. Throws when the service isolate is
  /// not reachable yet; the caller retries, and a failed attach must not
  /// close the exposed streams (they outlive the port).
  Future<void> attach() async {
    if (_attached) return;
    ui.IsolateNameServer.removePortNameMapping(kUiPortName);
    final port = ReceivePort();
    ui.IsolateNameServer.registerPortWithName(port.sendPort, kUiPortName);
    port.listen(_onMessage);
    _port = port;
    _attached = true;
    try {
      final keys = await _request('welcomeKeys', <String, dynamic>{});
      if (keys is Map) {
        keys.forEach((dynamic fp, dynamic key) {
          if (fp is String && key is String) _welcomeKeys[fp] = key;
        });
      }
      final snapshot = await _request('snapshot', <String, dynamic>{});
      if (snapshot is List) {
        for (final entry in snapshot) {
          final session = PendingSession.fromJson(
              Map<String, dynamic>.from(entry as Map));
          _pending.add(session);
        }
      }
      await _request('start', <String, dynamic>{});
    } catch (e) {
      await detach();
      rethrow;
    }
  }

  /// Unregisters and closes the UI port only; the streams stay open so a
  /// later [attach] can replay into them.
  Future<void> detach() async {
    if (!_attached) return;
    _attached = false;
    ui.IsolateNameServer.removePortNameMapping(kUiPortName);
    _port?.close();
    _port = null;
    for (final c in _inflight.values) {
      if (!c.isCompleted) c.completeError(StateError('bridge detached'));
    }
    _inflight.clear();
  }

  /// Final teardown: detach and close the exposed streams.
  Future<void> dispose() async {
    await detach();
    if (!_pending.isClosed) await _pending.close();
    if (!_decisions.isClosed) await _decisions.close();
    if (!_unregistered.isClosed) await _unregistered.close();
  }

  Future<dynamic> _request(
    String method,
    Map<String, dynamic> args, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final replyPort = _port;
    if (replyPort == null) {
      throw StateError('ui bridge not attached');
    }
    final service = ui.IsolateNameServer.lookupPortByName(kServicePortName);
    if (service == null) {
      throw StateError('background service isolate not registered');
    }
    final id = _nextRequestId++;
    final completer = Completer<Map<dynamic, dynamic>>();
    _inflight[id] = completer;
    service.send(<String, dynamic>{
      'type': 'request',
      'id': id,
      'method': method,
      'args': args,
      'replyTo': replyPort.sendPort,
    });
    final reply = await completer.future.timeout(timeout);
    _inflight.remove(id);
    final error = reply['error'];
    if (error != null) throw StateError('$error');
    return reply['value'];
  }

  void _onMessage(dynamic raw) {
    if (raw is! Map) return;
    switch (raw['type']) {
      case 'reply':
        final id = raw['id'];
        final completer = id is int ? _inflight[id] : null;
        completer?.complete(Map<dynamic, dynamic>.from(raw));
      case 'pending':
        final session = raw['session'];
        if (session is Map && !_pending.isClosed) {
          _pending.add(
              PendingSession.fromJson(Map<String, dynamic>.from(session)));
        }
      case 'decision':
        final result = raw['result'];
        if (result is Map && !_decisions.isClosed) {
          _decisions.add(
              DecisionResult.fromJson(Map<String, dynamic>.from(result)));
        }
        final myKey = raw['myKey'];
        final source = (raw['result'] as Map?)?['source'];
        if (myKey is String && source is String) _welcomeKeys[source] = myKey;
      case 'unregistered':
        final fingerprint = raw['fingerprint'];
        if (fingerprint is String && !_unregistered.isClosed) {
          _unregistered.add(fingerprint);
        }
    }
  }

  String? welcomeKeyFor(String fingerprint) => _welcomeKeys[fingerprint];

  Future<DecisionResult> postDecision({
    required PendingSession session,
    required String decision,
    required String signatureBase64,
  }) async {
    final value = await _request(
      'postDecision',
      <String, dynamic>{
        'session': session.toJson(),
        'decision': decision,
        'sig': signatureBase64,
      },
      timeout: const Duration(seconds: 20),
    );
    return DecisionResult.fromJson(Map<String, dynamic>.from(value as Map));
  }

  Future<void> forgetComputer(String fingerprint) =>
      _request('forgetComputer', <String, dynamic>{'fingerprint': fingerprint});

  /// Asks the service engine to hide the native overlay window (task 12).
  /// Idempotent: a no-op RPC when nothing is showing.
  Future<void> hideOverlay() =>
      _request('hideOverlay', const <String, dynamic>{});
}

/// UI-engine facade with the [ConnectionManager] surface. The approval screen
/// keeps talking to a [ConnectionManager]; in production this implementation
/// never dials — every operation rides the bridge to the service engine, the
/// single socket owner.
class ServiceLinkManager extends ConnectionManager {
  ServiceLinkManager({required super.keyStore, required super.identity});

  final UiBridge _bridge = UiBridge();
  Timer? _attachRetry;

  /// Whether the UI engine considers itself foregrounded (the approval screen
  /// is resumed). While false, [_attachWithRetry] never re-attaches, so the
  /// service engine's `_sendToUi` finds no registered `phonefprint.ui` port
  /// and routes alerts to the background path (overlay + notification).
  bool _foreground = true;

  @override
  Future<void> start() => _attachWithRetry();

  /// Lifecycle hook driven by the approval screen's [WidgetsBindingObserver].
  /// On background ([foreground] false: paused/hidden/detached) it detaches
  /// the UI bridge — unregistering the `phonefprint.ui` port, which is the
  /// service engine's "UI foregrounded" signal — while keeping the exposed
  /// streams open. A transient `inactive` (BiometricPrompt and other system
  /// dialogs pause the Activity without stopping it) counts as foreground so
  /// a decision RPC issued right after the prompt still finds the port. On
  /// resume/inactive it re-attaches, which re-registers the port and replays
  /// the pending snapshot.
  Future<void> setForeground(bool foreground) async {
    _foreground = foreground;
    if (foreground) {
      await _attachWithRetry();
    } else {
      _attachRetry?.cancel();
      _attachRetry = null;
      await _bridge.detach();
    }
  }

  Future<void> _attachWithRetry() async {
    _attachRetry?.cancel();
    try {
      await _bridge.attach();
    } catch (e) {
      debugPrint('phone-fprint-auth: ui bridge attach failed: $e');
      // Do not retry (and re-register the foreground port) while backgrounded.
      if (!_foreground) return;
      _attachRetry = Timer(
          const Duration(seconds: 5), () => unawaited(_attachWithRetry()));
    }
  }

  @override
  Stream<PendingSession> pending() => _bridge.pendingStream;

  @override
  Stream<DecisionResult> decisions() => _bridge.decisionsStream;

  @override
  Stream<String> unregistered() => _bridge.unregisteredStream;

  @override
  String? welcomeKeyFor(String fingerprint) => _bridge.welcomeKeyFor(fingerprint);

  @override
  Future<DecisionResult> postDecision({
    required PendingSession session,
    required String decision,
    required String signatureBase64,
  }) =>
      _bridge.postDecision(
        session: session,
        decision: decision,
        signatureBase64: signatureBase64,
      );

  @override
  Future<void> forgetComputer(String fingerprint) =>
      _bridge.forgetComputer(fingerprint);

  /// UI-side hook for task 12: hides the service-owned native overlay after
  /// an overlay-triggered approval ran in this Activity.
  Future<void> hideOverlay() => _bridge.hideOverlay();

  @override
  Future<void> dispose() async {
    _attachRetry?.cancel();
    _attachRetry = null;
    await _bridge.dispose();
  }
}
