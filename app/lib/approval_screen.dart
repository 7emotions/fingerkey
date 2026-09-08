/// Approval flow: receive pushed pending sudo/pkexec requests from the
/// daemon over the Bluetooth SPP link, pop the native biometric prompt, sign
/// the decision with the device key and send it back as a framed
/// `decision` message.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';

import 'daemon_client.dart';
import 'format.dart';
import 'key_store.dart';

class ApprovalScreen extends StatefulWidget {
  const ApprovalScreen({
    super.key,
    required this.identity,
    required this.daemonUrl,
    required this.certPin,
    required this.onReset,
  });

  final DeviceIdentity identity;

  /// Legacy daemon URL from the pre-Bluetooth pairing flow, shown for
  /// context only — the BT transport does not use it.
  final String daemonUrl;

  /// Legacy TLS certificate fingerprint from the pre-Bluetooth pairing
  /// flow; unused on the BT transport.
  final String certPin;

  /// Invoked when the user chooses to drop the current pairing and re-pair:
  /// the caller clears the stored identity/URL/pin and falls back to the
  /// pairing screen.
  final VoidCallback onReset;

  @override
  State<ApprovalScreen> createState() => _ApprovalScreenState();
}

class _ApprovalScreenState extends State<ApprovalScreen> {
  late final BtClient _client;
  final LocalAuthentication _auth = LocalAuthentication();
  StreamSubscription<PendingSession>? _sub;

  bool _disposed = false;
  bool _busy = false;
  PendingSession? _session;
  String _status = 'Listening for requests…';

  @override
  void initState() {
    super.initState();
    _client = BtClient();
    _sub = _client.pending().listen(
          _onSession,
          onError: (Object e, StackTrace st) {
            if (_disposed) return;
            setState(() => _status = 'BT link unavailable ($e).');
          },
        );
  }

  @override
  void dispose() {
    _disposed = true;
    unawaited(_sub?.cancel());
    _client.dispose();
    super.dispose();
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
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(widget.daemonUrl,
                        style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 12)),
                    const SizedBox(height: 4),
                    Text(_status, style: theme.textTheme.bodyMedium),
                  ],
                ),
              ),
              const SizedBox(height: 24),
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
