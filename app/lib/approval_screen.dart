/// Approval flow: long-poll the daemon for pending sudo/pkexec requests,
/// pop the native biometric prompt, sign the decision with the device key
/// and POST it back.
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
  });

  final DeviceIdentity identity;
  final String daemonUrl;

  @override
  State<ApprovalScreen> createState() => _ApprovalScreenState();
}

class _ApprovalScreenState extends State<ApprovalScreen> {
  late final DaemonClient _client;
  final LocalAuthentication _auth = LocalAuthentication();

  bool _disposed = false;
  bool _busy = false;
  PendingSession? _session;
  Completer<void>? _resolution;
  String _status = 'Listening for requests…';

  @override
  void initState() {
    super.initState();
    _client = DaemonClient(baseUrl: widget.daemonUrl);
    unawaited(_pollLoop());
  }

  @override
  void dispose() {
    _disposed = true;
    _client.close();
    super.dispose();
  }

  Future<void> _pollLoop() async {
    while (!_disposed) {
      PendingSession? session;
      try {
        session = await _client.pollPending();
      } catch (e) {
        if (_disposed) return;
        setState(() => _status = 'Daemon unreachable ($e). Retrying in 3 s…');
        await Future<void>.delayed(const Duration(seconds: 3));
        continue;
      }
      if (_disposed) return;
      if (session == null) continue; // 204 long-poll timeout — keep polling

      _resolution = Completer<void>();
      setState(() {
        _session = session;
        _status = 'Request pending — waiting for your decision.';
      });
      // Pop the native biometric prompt as soon as a session surfaces.
      unawaited(_approveWithBiometrics());
      // Wait until the session is approved or denied before polling again.
      await _resolution!.future;
    }
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
      final code = await _client.postDecision(
        sessionId: session.id,
        decision: decision,
        signatureBase64: sig,
      );
      if (_disposed) return;
      if (code == 200) {
        setState(() {
          _session = null;
          _status =
              'Decision "$decision" accepted. Listening for requests…';
        });
        _resolution?.complete();
      } else {
        setState(
            () => _status = 'Daemon rejected decision (HTTP $code). Retrying…');
        await Future<void>.delayed(const Duration(seconds: 3));
        if (!_disposed) _resolution?.complete(); // give the session back
      }
    } catch (e) {
      if (_disposed) return;
      setState(() => _status = 'Failed to send decision ($e). Retrying…');
      await Future<void>.delayed(const Duration(seconds: 3));
      if (!_disposed) _resolution?.complete();
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
      appBar: AppBar(title: const Text('PHONE FPRINT AUTH')),
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
