/// Approval flow: receive pushed pending sudo/pkexec requests from the
/// daemon over the Bluetooth SPP link, pop the native biometric prompt, sign
/// the decision with the device key and send it back as a framed
/// `decision` message. A connection banner shows the link state and
/// reconnects automatically when it drops.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';

import 'daemon_client.dart';
import 'format.dart';
import 'key_store.dart';

class ApprovalScreen extends StatefulWidget {
  const ApprovalScreen({
    super.key,
    required this.identity,
    required this.btAddress,
    required this.onReset,
    this.client,
  });

  final DeviceIdentity identity;

  /// MAC address of the paired daemon computer; the transport dials its SPP
  /// server here and reconnects to it when the link drops.
  final String btAddress;

  /// Invoked when the user chooses to drop the current pairing and re-pair:
  /// the caller clears the stored identity/address and falls back to the
  /// pairing screen.
  final VoidCallback onReset;

  /// The framed SPP client; injectable for tests, defaults to the real
  /// platform channel.
  final BtClient? client;

  @override
  State<ApprovalScreen> createState() => _ApprovalScreenState();
}

class _ApprovalScreenState extends State<ApprovalScreen> {
  static const Duration _reconnectDelay = Duration(seconds: 3);

  late final BtClient _client;
  final LocalAuthentication _auth = LocalAuthentication();
  StreamSubscription<PendingSession>? _sub;
  StreamSubscription<ConnectionStatus>? _connSub;
  Timer? _reconnectTimer;

  bool _disposed = false;
  bool _busy = false;
  bool _connecting = false;
  bool _connected = false;
  String? _connectedAddress;
  PendingSession? _session;
  String _status = 'Listening for requests…';

  @override
  void initState() {
    super.initState();
    _client = widget.client ?? BtClient();
    _sub = _client.pending().listen(
          _onSession,
          onError: (Object e, StackTrace st) {
            if (_disposed) return;
            setState(() => _status = 'BT link unavailable ($e).');
          },
        );
    _connSub = _client.connection().listen(_onConnection);
    unawaited(_reconnect());
  }

  @override
  void dispose() {
    _disposed = true;
    _reconnectTimer?.cancel();
    unawaited(_sub?.cancel());
    unawaited(_connSub?.cancel());
    _client.dispose();
    super.dispose();
  }

  void _onConnection(ConnectionStatus status) {
    if (_disposed) return;
    if (status.connected) {
      _reconnectTimer?.cancel();
      setState(() {
        _connected = true;
        _connectedAddress = status.address ?? _connectedAddress;
      });
    } else {
      _scheduleReconnect();
    }
  }

  /// Marks the link down and arms a reconnect attempt after
  /// [_reconnectDelay]. Re-arming collapses repeated events into a single
  /// pending attempt.
  void _scheduleReconnect() {
    if (_disposed) return;
    if (_connected) {
      setState(() {
        _connected = false;
        _connectedAddress = null;
      });
    }
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(_reconnectDelay, () {
      _reconnectTimer = null;
      unawaited(_reconnect());
    });
  }

  /// Dials the daemon at [btAddress]. An `already_connected` error means a
  /// socket is still active (e.g. just paired) — treat it as connected.
  Future<void> _reconnect() async {
    if (_disposed || _connecting) return;
    _connecting = true;
    try {
      await _client.connect(widget.btAddress);
      if (!_disposed) {
        setState(() {
          _connected = true;
          _connectedAddress = widget.btAddress;
        });
      }
    } on PlatformException catch (e) {
      if (!_disposed && e.code == 'already_connected') {
        setState(() {
          _connected = true;
          _connectedAddress = widget.btAddress;
        });
      } else {
        _scheduleReconnect();
      }
    } catch (_) {
      _scheduleReconnect();
    } finally {
      _connecting = false;
    }
  }

  /// A pending session pushed by the daemon: show it and pop the biometric
  /// prompt. Sessions arriving while one is already on screen are ignored
  /// (the daemon pushes at most one live session per request).
  void _onSession(PendingSession session) {
    if (_disposed || _session != null) return;
    setState(() {
      _session = session;
      _status = 'Request pending — waiting for your decision.';
    });
    unawaited(_approveWithBiometrics());
  }

  Future<void> _approveWithBiometrics() async {
    final session = _session;
    if (session == null || _busy) return;
    _busy = true;
    try {
      final canCheck = await _auth.canCheckBiometrics;
      final supported = await _auth.isDeviceSupported();
      if (!canCheck && !supported) {
        if (_disposed) return;
        setState(() => _status =
            'No biometric hardware available on this device.');
        return;
      }
      final ok = await _auth.authenticate(
        localizedReason: 'Approve for ${session.user} on ${session.service}',
        biometricOnly: true,
        persistAcrossBackgrounding: true,
      );
      if (_disposed) return;
      if (!ok) {
        setState(() => _status =
            'Biometric cancelled — tap APPROVE to retry, or DENY.');
        return;
      }
      await _sendDecision(session, kActionApprove);
    } on LocalAuthException catch (e) {
      if (_disposed) return;
      setState(() => _status = 'Biometric error: $e');
    } finally {
      _busy = false;
    }
  }

  Future<void> _sendDecision(PendingSession session, String decision) async {
    setState(() => _status = 'Sending $decision…');
    try {
      final sig = await signDecision(
        keyPair: widget.identity.keyPair,
        action: decision,
        user: session.user,
        service: session.service,
        tty: session.tty,
        nonce: session.nonce,
      );
      final result = await _client.postDecision(
        sessionId: session.id,
        decision: decision,
        signatureBase64: sig,
      );
      if (_disposed) return;
      if (!result.isError) {
        setState(() {
          _session = null;
          _status = 'Decision "$decision" accepted '
              '(${result.status ?? 'recorded'}). Listening for requests…';
        });
      } else {
        setState(() => _status =
            'Daemon rejected decision (${result.error}). Tap to retry.');
      }
    } catch (e) {
      if (_disposed) return;
      setState(() => _status = 'Failed to send decision ($e). Tap to retry.');
    }
  }

  void _deny() {
    final session = _session;
    if (session == null) return;
    unawaited(_sendDecision(session, kActionDeny));
  }

  Widget _connectionBanner() {
    final Color background;
    final Color foreground;
    final IconData icon;
    final String text;
    if (_connected) {
      background = const Color(0xFF123524);
      foreground = const Color(0xFF8CE0A8);
      icon = Icons.bluetooth_connected;
      text = 'connected to ${_connectedAddress ?? widget.btAddress}';
    } else {
      background = const Color(0xFF3B1D1D);
      foreground = const Color(0xFFF0B4B4);
      icon = Icons.bluetooth_disabled;
      text = 'disconnected — reconnecting…';
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(icon, size: 18, color: foreground),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: TextStyle(
                color: foreground,
                fontFamily: 'monospace',
                fontSize: 12,
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final session = _session;
    return Scaffold(
      appBar: AppBar(
        title: const Text('PHONE FPRINT AUTH'),
        actions: [
          IconButton(
            tooltip: 'Re-pair device',
            icon: const Icon(Icons.settings),
            onPressed: widget.onReset,
          ),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _connectionBanner(),
              const SizedBox(height: 12),
              Text(_status, style: theme.textTheme.bodyMedium),
              const SizedBox(height: 16),
              Expanded(
                child: session == null
                    ? Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.fingerprint,
                                size: 72,
                                color: theme.colorScheme.outlineVariant),
                            const SizedBox(height: 16),
                            Text('No pending requests',
                                style: theme.textTheme.titleMedium),
                          ],
                        ),
                      )
                    : _SessionCard(session: session),
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed:
                    session == null || _busy ? null : _approveWithBiometrics,
                icon: const Icon(Icons.fingerprint),
                label: const Text('APPROVE'),
              ),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: session == null ? null : _deny,
                icon: const Icon(Icons.block),
                label: const Text('DENY'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SessionCard extends StatelessWidget {
  const _SessionCard({required this.session});

  final PendingSession session;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Approve sudo/pkexec for ${session.user} on '
                '${session.service}?'),
            const SizedBox(height: 16),
            _row(theme, 'USER', session.user),
            _row(theme, 'SERVICE', session.service),
            _row(theme, 'TTY', session.tty.isEmpty ? '(none)' : session.tty),
            _row(theme, 'SESSION', session.id),
          ],
        ),
      ),
    );
  }

  Widget _row(ThemeData theme, String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 72,
            child: Text(label,
                style: theme.textTheme.labelSmall
                    ?.copyWith(color: theme.colorScheme.outline)),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 13)),
          ),
        ],
      ),
    );
  }
}
