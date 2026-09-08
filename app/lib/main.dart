import 'package:flutter/material.dart';

import 'approval_screen.dart';
import 'key_store.dart';
import 'pairing_screen.dart';

void main() {
  runApp(const PhoneFprintApp());
}

class _Bootstrap {
  const _Bootstrap(
      this.keyStore, this.identity, this.daemonUrl, this.storedUrl, this.certPin);

  final KeyStore keyStore;
  final DeviceIdentity? identity;

  /// Effective (sanitized, https) daemon URL.
  final String daemonUrl;

  /// Raw stored daemon URL (may be null or a leftover non-https value).
  final String? storedUrl;

  /// 64-hex TLS certificate pin, or null when not yet paired.
  final String? certPin;
}

class PhoneFprintApp extends StatefulWidget {
  const PhoneFprintApp({super.key});

  @override
  State<PhoneFprintApp> createState() => _PhoneFprintAppState();
}

class _PhoneFprintAppState extends State<PhoneFprintApp> {
  final Future<_Bootstrap> _bootstrap = _load();
  DeviceIdentity? _identity;
  String? _daemonUrl;
  String? _storedUrl;
  String? _certPin;

  static Future<_Bootstrap> _load() async {
    final keyStore = KeyStore();
    final identity = await keyStore.load();
    final storedUrl = await keyStore.daemonUrlStored();
    final certPin = await keyStore.certPin();
    return _Bootstrap(
      keyStore,
      identity,
      KeyStore.effectiveDaemonUrl(storedUrl),
      storedUrl,
      certPin,
    );
  }

  void _onPaired(DeviceIdentity identity, String daemonUrl, String certPin) {
    setState(() {
      _identity = identity;
      _daemonUrl = daemonUrl;
      _storedUrl = daemonUrl;
      _certPin = certPin;
    });
  }

  @override
  Widget build(BuildContext context) {
    const accent = Color(0xFFFFB000);
    final colorScheme = ColorScheme.fromSeed(
      seedColor: accent,
      brightness: Brightness.dark,
    );
    return MaterialApp(
      title: 'phone-fprint-auth',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: colorScheme.copyWith(surface: const Color(0xFF0B0E11)),
        scaffoldBackgroundColor: const Color(0xFF0B0E11),
        useMaterial3: true,
      ),
      home: FutureBuilder<_Bootstrap>(
        future: _bootstrap,
        builder: (context, snapshot) {
          final data = snapshot.data;
          if (snapshot.hasError) {
            return Scaffold(
              body: Center(child: Text('Startup failed: ${snapshot.error}')),
            );
          }
          if (data == null) {
            return const Scaffold(
              body: Center(child: CircularProgressIndicator()),
            );
          }
          final identity = _identity ?? data.identity;
          final daemonUrl = _daemonUrl ?? data.daemonUrl;
          final storedUrl = _storedUrl ?? data.storedUrl;
          final certPin = _certPin ?? data.certPin;
          if (identity == null) {
            return FutureBuilder<DeviceIdentity>(
              future: data.keyStore.generate(),
              builder: (context, genSnapshot) {
                final generated = genSnapshot.data;
                if (generated == null) {
                  return const Scaffold(
                    body: Center(child: CircularProgressIndicator()),
                  );
                }
                return PairingScreen(
                  keyStore: data.keyStore,
                  identity: generated,
                  initialUrl: daemonUrl,
                  initialPin: certPin ?? '',
                  onPaired: _onPaired,
                );
              },
            );
          }
          if (KeyStore.needsPairing(storedUrl, certPin)) {
            // No pin yet, or a leftover non-https URL: re-enter both.
            return PairingScreen(
              keyStore: data.keyStore,
              identity: identity,
              initialUrl: daemonUrl,
              initialPin: certPin ?? '',
              onPaired: _onPaired,
            );
          }
          return ApprovalScreen(
            identity: identity,
            daemonUrl: daemonUrl,
            certPin: certPin!,
          );
        },
      ),
    );
  }
}
