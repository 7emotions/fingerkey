import 'package:flutter/material.dart';

import 'approval_screen.dart';
import 'key_store.dart';
import 'pairing_screen.dart';

void main() {
  runApp(const PhoneFprintApp());
}

class _Bootstrap {
  const _Bootstrap(this.keyStore, this.identity, this.daemonUrl);

  final KeyStore keyStore;
  final DeviceIdentity? identity;
  final String daemonUrl;
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

  static Future<_Bootstrap> _load() async {
    final keyStore = KeyStore();
    final identity = await keyStore.load();
    final daemonUrl = await keyStore.daemonUrl();
    return _Bootstrap(keyStore, identity, daemonUrl);
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
                  onPaired: (id, url) => setState(() {
                    _identity = id;
                    _daemonUrl = url;
                  }),
                );
              },
            );
          }
          return ApprovalScreen(identity: identity, daemonUrl: daemonUrl);
        },
      ),
    );
  }
}
