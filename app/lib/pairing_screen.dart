/// First-launch pairing: generate (or show) the Ed25519 device key, present
/// the public key as copyable text for registration on the daemon (the
/// computer has no camera, so a pubkey QR there is useless), and configure
/// the HTTPS daemon URL plus the TLS certificate fingerprint.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import 'key_store.dart';
import 'pairing_qr.dart';

class PairingScreen extends StatefulWidget {
  const PairingScreen({
    super.key,
    required this.keyStore,
    required this.identity,
    required this.initialUrl,
    required this.initialPin,
    required this.onPaired,
  });

  final KeyStore keyStore;
  final DeviceIdentity identity;
  final String initialUrl;
  final String initialPin;
  final void Function(DeviceIdentity identity, String daemonUrl, String certPin)
      onPaired;

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  late final TextEditingController _urlController;
  late final TextEditingController _pinController;

  @override
  void initState() {
    super.initState();
    _urlController = TextEditingController(text: widget.initialUrl);
    _pinController = TextEditingController(text: widget.initialPin);
    // Emit the pubkey to logcat so an agent on the machine can retrieve it
    // with `adb logcat -d | grep 'phone-fprint-auth pubkey'` and run
    // `phone-approve pair <name> <pubkey>` without the user copying it.
    debugPrint('phone-fprint-auth pubkey: '
        '${widget.identity.publicKeyBase64}');
  }

  @override
  void dispose() {
    _urlController.dispose();
    _pinController.dispose();
    super.dispose();
  }

  Future<void> _copyPublicKey() async {
    await Clipboard.setData(
        ClipboardData(text: widget.identity.publicKeyBase64));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Public key copied to clipboard')),
    );
  }

  Future<void> _scanQr() async {
    final info = await Navigator.of(context).push<PairingInfo>(
      MaterialPageRoute(builder: (_) => const _QrScanScreen()),
    );
    if (info == null || !mounted) return;
    _urlController.text = info.url;
    _pinController.text = info.pin;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
          content: Text('QR scanned — daemon URL and fingerprint filled')),
    );
  }

  Future<void> _continue() async {
    final url = _urlController.text.trim();
    if (!KeyStore.isHttpsUrl(url)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a valid https:// daemon URL')),
      );
      return;
    }
    // The normative pin form is 64 lowercase hex; accept mixed case input
    // and normalize.
    final pin = _pinController.text.trim().toLowerCase();
    if (!KeyStore.isHexPin(pin)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text('Enter the 64-character certificate fingerprint '
                '(SHA-256, hex)')),
      );
      return;
    }
    await widget.keyStore.setDaemonUrl(url);
    await widget.keyStore.setCertPin(pin);
    widget.onPaired(widget.identity, url, pin);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('PAIR DEVICE')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Text(
              'Register this phone on the daemon',
              style: theme.textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              'Copy this base64 public key and add it on the computer with '
              '`phone-approve pair <name> <pubkey>`.',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 24),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                widget.identity.publicKeyBase64,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                onPressed: _copyPublicKey,
                icon: const Icon(Icons.copy, size: 18),
                label: const Text('COPY'),
              ),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: _scanQr,
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('SCAN QR'),
            ),
            Center(
              child: Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(
                  'Run `phone-approve pair-qr` on the computer and point the '
                  'camera at the code it prints.',
                  style: theme.textTheme.bodySmall,
                  textAlign: TextAlign.center,
                ),
              ),
            ),
            const Divider(height: 32),
            Text(
              '…or enter the details manually',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _urlController,
              keyboardType: TextInputType.url,
              decoration: const InputDecoration(
                labelText: 'Daemon URL (https)',
                hintText: KeyStore.defaultDaemonUrl,
                border: OutlineInputBorder(),
              ),
              style: const TextStyle(fontFamily: 'monospace'),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _pinController,
              keyboardType: TextInputType.text,
              autocorrect: false,
              enableSuggestions: false,
              decoration: const InputDecoration(
                labelText: 'Certificate fingerprint (64 hex)',
                hintText: 'SHA-256 of the daemon TLS certificate',
                helperText: 'phone-approve tls-fingerprint',
                border: OutlineInputBorder(),
              ),
              style: const TextStyle(fontFamily: 'monospace'),
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: _continue,
              icon: const Icon(Icons.fingerprint),
              label: const Text('START LISTENING'),
            ),
          ],
        ),
      ),
    );
  }
}

/// Full-screen camera view that scans the pairing QR shown by the computer's
/// `phone-approve pair-qr`. Pops with the validated [PairingInfo] on success;
/// on a malformed QR it tells the operator and keeps scanning.
class _QrScanScreen extends StatefulWidget {
  const _QrScanScreen();

  @override
  State<_QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<_QrScanScreen> {
  /// Set once a valid pairing QR has been parsed; guards against onDetect
  /// firing again while the route is being popped.
  bool _handled = false;

  /// The last payload that was shown to the operator as invalid, so the
  /// error SnackBar is not re-shown for the same QR on every frame.
  String? _lastRejectedRaw;

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    final rawValue =
        capture.barcodes.isEmpty ? null : capture.barcodes.first.rawValue;
    if (rawValue == null || rawValue.isEmpty) return;

    final info = parsePairingQr(rawValue);
    if (info == null) {
      if (rawValue == _lastRejectedRaw) return;
      _lastRejectedRaw = rawValue;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text('not a phone-fprint-auth pairing QR')),
      );
      return;
    }

    _handled = true;
    Navigator.of(context).pop(info);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(title: const Text('SCAN PAIRING QR')),
      body: Column(
        children: [
          Expanded(
            child: MobileScanner(
              onDetect: _onDetect,
              errorBuilder: (context, error) =>
                  _ScannerErrorView(error: error),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              'Point the camera at the QR printed by\n'
              '`phone-approve pair-qr`',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: Colors.white70),
            ),
          ),
        ],
      ),
    );
  }
}

class _ScannerErrorView extends StatelessWidget {
  const _ScannerErrorView({required this.error});

  final MobileScannerException error;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ColoredBox(
      color: Colors.black,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.no_photography,
                  color: Colors.white, size: 48),
              const SizedBox(height: 16),
              Text(
                error.errorCode.message,
                textAlign: TextAlign.center,
                style: theme.textTheme.titleMedium
                    ?.copyWith(color: Colors.white),
              ),
              if (error.errorDetails?.message case final String message) ...[
                const SizedBox(height: 8),
                Text(
                  message,
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: Colors.white70),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
