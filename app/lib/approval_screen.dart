/// Multi-computer approval flow: the [ConnectionManager] keeps one TLS link
/// per roster computer and aggregates their pending requests; this screen
/// shows one card per request (tagged with the source computer) with a
/// monotonic deadline countdown, prompts for biometrics when the user taps
/// APPROVE, and reconciles cards that another phone decided or that expired.
/// The gear menu
/// splits "forget this computer" (keeps the key) from "reset identity"
/// (wipes the key + roster).
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';

import 'connection_manager.dart';
import 'daemon_client.dart';
import 'format.dart';
import 'key_store.dart';

class ApprovalScreen extends StatefulWidget {
  const ApprovalScreen({
    super.key,
    required this.identity,
    required this.keyStore,
    required this.roster,
    required this.onReset,
    required this.onRosterChanged,
    this.manager,
    this.authenticate,
  });

  final DeviceIdentity identity;
  final KeyStore keyStore;

  /// The current roster, used for the connection banner and the "forget"
  /// menu. Refreshed by the caller after a forget.
  final List<RosterComputer> roster;

  /// Full identity reset (wipe key + roster).
  final VoidCallback onReset;

  /// The roster changed (a computer was forgotten); the caller re-reads it
  /// and falls back to pairing when it emptied.
  final VoidCallback onRosterChanged;

  /// The connection manager; injectable for tests, otherwise built here.
  final ConnectionManager? manager;

  /// Test seam: runs the biometric prompt and returns whether the user
  /// authenticated. Defaults to the real [LocalAuthentication] flow.
  final Future<bool> Function(String reason)? authenticate;

  @override
  State<ApprovalScreen> createState() => _ApprovalScreenState();
}

class _ApprovalScreenState extends State<ApprovalScreen> {
  late final ConnectionManager _manager =
      widget.manager ??
      ConnectionManager(keyStore: widget.keyStore, identity: widget.identity);

  final LocalAuthentication _auth = LocalAuthentication();

  StreamSubscription<PendingSession>? _pendingSub;
  StreamSubscription<DecisionResult>? _decisionsSub;
  StreamSubscription<String>? _unregisteredSub;
  Timer? _ticker;

  bool _disposed = false;
  bool _busy = false;
  String _status = 'Listening for requests…';
  final List<_RequestCard> _cards = <_RequestCard>[];

  @override
  void initState() {
    super.initState();
    _pendingSub = _manager.pending().listen(_onPending);
    _decisionsSub = _manager.decisions().listen(_onDecisionResult);
    _unregisteredSub = _manager.unregistered().listen(_onUnregistered);
    _ticker = Timer.periodic(const Duration(seconds: 1), _tick);
    unawaited(_manager.start());
  }

  @override
  void dispose() {
    _disposed = true;
    _ticker?.cancel();
    unawaited(_pendingSub?.cancel());
    unawaited(_decisionsSub?.cancel());
    unawaited(_unregisteredSub?.cancel());
    unawaited(_manager.dispose());
    super.dispose();
  }

  void _onPending(PendingSession session) {
    if (_disposed) return;
    final dup = _cards.any((c) =>
        c.session.id == session.id && c.session.source == session.source);
    if (dup) return;
    final card = _RequestCard(session);
    setState(() {
      _cards.add(card);
      _status =
          'Request pending — review reason/command, then approve or deny.';
    });
    // The card is shown first; the biometric prompt fires only when the user
    // taps APPROVE (see _RequestCardView.onApprove).
  }

  void _onDecisionResult(DecisionResult result) {
    if (_disposed) return;
    if (result.isExpired) {
      if (_removeCardsWhere((c) => _matches(c, result))) {
        _toast('请求已过期');
      }
      return;
    }
    if (result.status == 'approved' || result.status == 'denied') {
      final source = result.source;
      final myKey = source == null ? null : _manager.welcomeKeyFor(source);
      // Our own decision is already cleared by postDecision; only act when a
      // different key (another phone) decided, so we surface "approved by X".
      if (myKey != null && result.key != null && result.key != myKey) {
        if (_removeCardsWhere((c) => _matches(c, result))) {
          _toast('已被 ${result.key} '
              '${result.status == 'approved' ? '批准' : '拒绝'}');
        }
      }
    }
  }

  void _onUnregistered(String fingerprint) {
    if (_disposed) return;
    String? name;
    for (final computer in widget.roster) {
      if (computer.fingerprint == fingerprint) {
        name = computer.name;
        break;
      }
    }
    // Clear that computer's in-flight cards ("密钥已失效").
    _removeCardsWhere((c) => c.session.source == fingerprint);
    final label = name == null ? '此电脑' : '此电脑（$name）';
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('密钥已失效'),
        content: Text('$label 不再认可此密钥，重新配对？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('知道了'),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              _forgetByFingerprint(fingerprint);
            },
            child: const Text('忘记此电脑'),
          ),
        ],
      ),
    );
  }

  bool _matches(_RequestCard card, DecisionResult result) =>
      card.session.id == result.id && card.session.source == result.source;

  void _tick(Timer _) {
    if (_disposed) return;
    setState(() {
      for (final card in _cards) {
        if (!card.expired) {
          card.remaining -= const Duration(seconds: 1);
          if (card.remaining.isNegative) card.remaining = Duration.zero;
        }
      }
    });
  }

  bool _removeCardsWhere(bool Function(_RequestCard) test) {
    final before = _cards.length;
    setState(() => _cards.removeWhere(test));
    return _cards.length < before;
  }

  void _removeCard(_RequestCard card) {
    if (!mounted) return;
    setState(() => _cards.remove(card));
  }

  void _toast(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _approve(_RequestCard card) async {
    if (_busy || card.expired) return;
    _busy = true;
    try {
      final reason =
          'Approve for ${card.session.user} on ${card.session.service}';
      final ok = await (widget.authenticate?.call(reason) ??
          _authenticateWithBiometrics(reason));
      if (_disposed) return;
      if (!ok) {
        setState(() => _status = 'Biometric cancelled — tap APPROVE to retry.');
        return;
      }
      await _sendDecision(card, kActionApprove);
    } on LocalAuthException catch (e) {
      if (_disposed) return;
      setState(() => _status = 'Biometric error: $e');
    } finally {
      _busy = false;
    }
  }

  Future<bool> _authenticateWithBiometrics(String reason) async {
    final canCheck = await _auth.canCheckBiometrics;
    final supported = await _auth.isDeviceSupported();
    if (!canCheck && !supported) {
      if (_disposed) return false;
      setState(() => _status = 'No biometric hardware available.');
      return false;
    }
    return _auth.authenticate(
      localizedReason: reason,
      biometricOnly: true,
      persistAcrossBackgrounding: true,
    );
  }

  void _deny(_RequestCard card) {
    if (card.expired) return;
    unawaited(_sendDecision(card, kActionDeny));
  }

  Future<void> _sendDecision(_RequestCard card, String decision) async {
    try {
      final sig = await signDecision(
        keyPair: widget.identity.keyPair,
        action: decision,
        user: card.session.user,
        service: card.session.service,
        tty: card.session.tty,
        nonce: card.session.nonce,
      );
      final result = await _manager.postDecision(
        session: card.session,
        decision: decision,
        signatureBase64: sig,
      );
      if (_disposed) return;
      if (!result.isError) {
        _removeCard(card);
        setState(() => _status =
            'Decision "$decision" accepted (${result.status ?? 'recorded'}).');
      } else {
        setState(() => _status = 'Daemon rejected decision (${result.error}).');
      }
    } catch (_) {
      if (_disposed) return;
      // The card stays in-flight; the client re-posts the decision idempotently
      // on reconnect so the verdict is not lost.
      setState(() => _status = 'Sending… will retry on reconnect.');
    }
  }

  void _showMenu() {
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.computer),
              title: Text(
                'Paired computers (${widget.roster.length})',
                style: Theme.of(ctx).textTheme.labelLarge,
              ),
            ),
            for (final computer in widget.roster)
              ListTile(
                leading: const Icon(Icons.link_off),
                title: Text('Forget ${computer.name}'),
                subtitle: Text(
                  computer.fingerprint,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
                onTap: () {
                  Navigator.pop(ctx);
                  _forget(computer);
                },
              ),
            const Divider(),
            ListTile(
              leading: const Icon(Icons.delete_forever,
                  color: Color(0xFFF0B4B4)),
              title: const Text(
                'Reset identity',
                style: TextStyle(color: Color(0xFFF0B4B4)),
              ),
              subtitle: const Text('Delete this phone\'s key and all pairings'),
              onTap: () {
                Navigator.pop(ctx);
                widget.onReset();
              },
            ),
          ],
        ),
      ),
    );
  }

  void _forget(RosterComputer computer) {
    _forgetByFingerprint(computer.fingerprint);
  }

  void _forgetByFingerprint(String fingerprint) {
    _manager.forgetComputer(fingerprint).then((_) {
      if (!mounted) return;
      widget.onRosterChanged();
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('PHONE FPRINT AUTH'),
        actions: [
          IconButton(
            tooltip: 'Clear all requests',
            icon: const Icon(Icons.close),
            onPressed: () => _removeCardsWhere((_) => true),
          ),
          IconButton(
            tooltip: 'Settings',
            icon: const Icon(Icons.settings),
            onPressed: _showMenu,
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
                child: _cards.isEmpty
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
                    : ListView(
                        children: [
                          for (final card in _cards)
                            Dismissible(
                              key: ValueKey(
                                  '${card.session.id}:${card.session.source}'),
                              onDismissed: (_) => _removeCard(card),
                              child: _RequestCardView(
                                card: card,
                                busy: _busy,
                                onApprove: () => _approve(card),
                                onDeny: () => _deny(card),
                              ),
                            ),
                        ],
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _connectionBanner() {
    final n = widget.roster.length;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: const Color(0xFF123524),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          const Icon(Icons.lan, size: 18, color: Color(0xFF8CE0A8)),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              'listening on $n computer${n == 1 ? '' : 's'}',
              style: const TextStyle(
                color: Color(0xFF8CE0A8),
                fontFamily: 'monospace',
                fontSize: 12,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _RequestCard {
  _RequestCard(this.session) {
    final rem = session.expiresAt.difference(DateTime.now());
    remaining = rem.isNegative ? Duration.zero : rem;
  }

  final PendingSession session;
  Duration remaining = Duration.zero;

  bool get expired => remaining <= Duration.zero;
}

class _RequestCardView extends StatelessWidget {
  const _RequestCardView({
    required this.card,
    required this.busy,
    required this.onApprove,
    required this.onDeny,
  });

  final _RequestCard card;
  final bool busy;
  final VoidCallback onApprove;
  final VoidCallback onDeny;

  static String _format(Duration d) {
    final s = d.inSeconds;
    if (s < 60) return '${s}s';
    final m = s ~/ 60;
    final rem = s % 60;
    return '$m:${rem.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final session = card.session;
    final expired = card.expired;
    final computer = session.sourceName ?? '(unknown computer)';
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.computer, size: 16),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    computer,
                    style: theme.textTheme.labelLarge,
                  ),
                ),
                Text(
                  expired ? 'expired' : _format(card.remaining),
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: expired
                        ? theme.colorScheme.error
                        : theme.colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text('Approve sudo/pkexec for ${session.user} on '
                '${session.service}?'),
            const SizedBox(height: 12),
            _row(theme, 'USER', session.user),
            _row(theme, 'SERVICE', session.service),
            _row(theme, 'TTY', session.tty.isEmpty ? '(none)' : session.tty),
            if (session.reason.isNotEmpty)
              _row(theme, 'REASON', session.reason),
            if (session.command.isNotEmpty)
              _row(theme, 'COMMAND', session.command),
            _row(theme, 'SESSION', session.id),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    onPressed: expired || busy ? null : onApprove,
                    icon: const Icon(Icons.fingerprint),
                    label: const Text('APPROVE'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: expired || busy ? null : onDeny,
                    icon: const Icon(Icons.block),
                    label: const Text('DENY'),
                  ),
                ),
              ],
            ),
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
