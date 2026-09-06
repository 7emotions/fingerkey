/// First-launch pairing: generate (or show) the Ed25519 device key, present
/// the public key as a QR code + copy button for registration on the daemon,
/// and configure the daemon URL.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'key_store.dart';

class PairingScreen extends StatefulWidget {
  const PairingScreen({
    super.key,
    required this.keyStore,
    required this.identity,
    required this.initialUrl,
    required this.onPaired,
  });

  final KeyStore keyStore;
  final DeviceIdentity identity;
  final String initialUrl;
  final void Function(DeviceIdentity identity, String daemonUrl) onPaired;

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  late final TextEditingController _urlController;

  @override
  void initState() {
    super.initState();
    _urlController = TextEditingController(text: widget.initialUrl);
  }

  @override
  void dispose() {
    _urlController.dispose();
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

  Future<void> _continue() async {
    final url = _urlController.text.trim();
    final uri = Uri.tryParse(url);
    if (uri == null || (uri.scheme != 'http' && uri.scheme != 'https')) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a valid http(s) daemon URL')),
      );
      return;
    }
    await widget.keyStore.setDaemonUrl(url);
    widget.onPaired(widget.identity, url);
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
              'Scan the QR or paste this base64 public key into the '
              'daemon\'s registered devices.',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 24),
            Center(
              child: Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: QrImageView(
                  data: widget.identity.publicKeyBase64,
                  version: QrVersions.auto,
                  size: 220,
                ),
              ),
            ),
            const SizedBox(height: 16),
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
            TextField(
              controller: _urlController,
              keyboardType: TextInputType.url,
              decoration: const InputDecoration(
                labelText: 'Daemon URL',
                hintText: KeyStore.defaultDaemonUrl,
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
