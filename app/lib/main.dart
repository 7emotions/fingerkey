import 'package:flutter/material.dart';

import 'approval_screen.dart';
import 'key_store.dart';
import 'pairing_screen.dart';

void main() {
  runApp(const PhoneFprintApp());
}

class _Bootstrap {
  const _Bootstrap(this.keyStore, this.identity, this.btAddress);

  final KeyStore keyStore;
  final DeviceIdentity? identity;

  /// MAC address of the paired daemon computer, or null when not yet paired.
  final String? btAddress;
}

class PhoneFprintApp extends StatefulWidget {
  const PhoneFprintApp({super.key});

  @override
  State<PhoneFprintApp> createState() => _PhoneFprintAppState();
}

class _PhoneFprintAppState extends State<PhoneFprintApp> {
  final Future<_Bootstrap> _bootstrap = _load();
  DeviceIdentity? _identity;
  String? _btAddress;

  /// True after a re-pair reset: the bootstrap values must be ignored and
  /// the pairing screen shown with a freshly generated identity.
  bool _reset = false;

  /// Fresh-identity generation for the reset path; memoized so rebuilds do
  /// not regenerate (and re-store) a new keypair every frame.
  Future<DeviceIdentity>? _generation;

  static Future<_Bootstrap> _load() async {
    final keyStore = KeyStore();
    final identity = await keyStore.load();
    final btAddress = await keyStore.btAddress();
    return _Bootstrap(keyStore, identity, btAddress);
  }

  void _onPaired(DeviceIdentity identity, String btAddress) {
    setState(() {
      _reset = false;
      _generation = null;
      _identity = identity;
      _btAddress = btAddress;
    });
  }

  /// Re-pair: wipe the stored Bluetooth address and Ed25519 private key,
  /// then fall back to the pairing screen, which generates a fresh identity.
  Future<void> _onReset() async {
    final data = await _bootstrap;
    await data.keyStore.clear();
    if (!mounted) return;
    setState(() {
      _reset = true;
      _identity = null;
      _btAddress = null;
      _generation = data.keyStore.generate();
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
          final identity = _reset ? null : (_identity ?? data.identity);
          final btAddress = _reset ? null : (_btAddress ?? data.btAddress);
          if (identity == null) {
            return FutureBuilder<DeviceIdentity>(
              future: _generation ?? data.keyStore.generate(),
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
                  onPaired: _onPaired,
                );
              },
            );
          }
          if (btAddress == null) {
            // Key exists but no paired computer yet: connect + authorize.
            return PairingScreen(
              keyStore: data.keyStore,
              identity: identity,
              onPaired: _onPaired,
            );
          }
          return ApprovalScreen(
            identity: identity,
            btAddress: btAddress,
            onReset: _onReset,
          );
        },
      ),
    );
  }
}
