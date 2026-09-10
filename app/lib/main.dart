import 'dart:async';

import 'package:flutter/material.dart';

import 'approval_screen.dart';
import 'key_store.dart';
import 'pairing_screen.dart';

void main() {
  runApp(const PhoneFprintApp());
}

class PhoneFprintApp extends StatefulWidget {
  const PhoneFprintApp({super.key});

  @override
  State<PhoneFprintApp> createState() => _PhoneFprintAppState();
}

class _PhoneFprintAppState extends State<PhoneFprintApp> {
  final KeyStore _keyStore = KeyStore();

  DeviceIdentity? _identity;
  List<RosterComputer> _roster = const [];
  bool _loading = true;

  /// Fresh-identity generation for first launch/reset; memoized so rebuilds
  /// never regenerate (and re-store) a new keypair every frame.
  Future<DeviceIdentity>? _generation;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  Future<void> _load() async {
    final identity = await _keyStore.load();
    final roster = await _keyStore.roster();
    if (!mounted) return;
    setState(() {
      _identity = identity;
      _roster = roster;
      _loading = false;
    });
  }

  Future<DeviceIdentity> _ensureIdentity() =>
      _generation ??= _keyStore.generate();

  /// A pairing screen finished: the roster now has at least one computer, so
  /// re-read it and move to the approval screen with [identity].
  void _onPaired(DeviceIdentity identity) {
    _keyStore.roster().then((r) {
      if (!mounted) return;
      setState(() {
        _identity = identity;
        _roster = r;
      });
    });
  }

  /// A computer was forgotten from the approval screen; re-read the roster.
  /// When it emptied, the build falls back to the pairing screen.
  void _onRosterChanged() {
    _keyStore.roster().then((r) {
      if (!mounted) return;
      setState(() => _roster = r);
    });
  }

  /// Full identity reset: wipe the key and roster, then pair from scratch.
  Future<void> _onReset() async {
    await _keyStore.resetIdentity();
    if (!mounted) return;
    setState(() {
      _identity = null;
      _roster = const [];
      _generation = null;
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
      home: _buildHome(),
    );
  }

  Widget _buildHome() {
    if (_loading) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }
    final identity = _identity;
    if (identity == null) {
      // First launch (or after reset): generate the identity once (memoized),
      // then show the pairing screen.
      return FutureBuilder<DeviceIdentity>(
        future: _ensureIdentity(),
        builder: (context, snapshot) {
          final generated = snapshot.data;
          if (generated == null) {
            return const Scaffold(
              body: Center(child: CircularProgressIndicator()),
            );
          }
          return PairingScreen(
            keyStore: _keyStore,
            identity: generated,
            onPaired: _onPaired,
          );
        },
      );
    }
    if (_roster.isEmpty) {
      // Key exists but no paired computer yet: pair.
      return PairingScreen(
        keyStore: _keyStore,
        identity: identity,
        onPaired: _onPaired,
      );
    }
    return ApprovalScreen(
      identity: identity,
      keyStore: _keyStore,
      roster: _roster,
      onReset: _onReset,
      onRosterChanged: _onRosterChanged,
    );
  }
}
