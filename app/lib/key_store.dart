/// Device identity (Ed25519 keypair in Keystore-backed secure storage) plus
/// the roster of paired daemon computers. The roster replaces the old single
/// `bt_address`: each entry is `{name, fingerprint, lastAddr}` where `name`
/// is the computer's display name (from the QR `n=` or the mDNS instance),
/// `fingerprint` is the pinned lowercase-hex SHA-256 of its TLS leaf cert,
/// and `lastAddr` is the last known `host:port`.
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class DeviceIdentity {
  const DeviceIdentity({required this.keyPair, required this.publicKeyBase64});

  final SimpleKeyPair keyPair;

  /// Standard (padded) base64 of the raw 32-byte Ed25519 public key.
  /// This is the string the daemon registers during pairing.
  final String publicKeyBase64;
}

/// One paired computer in the roster.
class RosterComputer {
  const RosterComputer({
    required this.name,
    required this.fingerprint,
    required this.lastAddr,
  });

  factory RosterComputer.fromJson(Map<String, dynamic> json) => RosterComputer(
        name: json['name'] as String? ?? '',
        fingerprint: json['fingerprint'] as String? ?? '',
        lastAddr: json['lastAddr'] as String? ?? '',
      );

  final String name;
  final String fingerprint;
  final String lastAddr;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'name': name,
        'fingerprint': fingerprint,
        'lastAddr': lastAddr,
      };
}

class KeyStore {
  static const String _kPrivateKey = 'ed25519_private_key';
  static const String _kRoster = 'roster';
  static const String _kSoundEnabled = 'sound_enabled';

  /// Mirrors "is the roster non-empty" into a native-readable SharedPreferences
  /// flag (task 13): the Android boot receiver cannot read
  /// FlutterSecureStorage, so it reads this marker instead and only restarts
  /// the foreground service when the app is configured. Handled natively by
  /// KeepalivePrefs.kt on both engines.
  static const MethodChannel _keepaliveChannel =
      MethodChannel('com.phonefprint.auth/keepalive');

  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  Future<DeviceIdentity?> load() async {
    final seedB64 = await _storage.read(key: _kPrivateKey);
    if (seedB64 == null) return null;
    final keyPair = await Ed25519().newKeyPairFromSeed(base64.decode(seedB64));
    return _identityFor(keyPair);
  }

  Future<DeviceIdentity> generate() async {
    final keyPair = await Ed25519().newKeyPair();
    final seed = await keyPair.extractPrivateKeyBytes();
    await _storage.write(key: _kPrivateKey, value: base64.encode(seed));
    return _identityFor(keyPair);
  }

  Future<DeviceIdentity> loadOrGenerate() async =>
      await load() ?? await generate();

  Future<DeviceIdentity> _identityFor(SimpleKeyPair keyPair) async {
    final publicKey = await keyPair.extractPublicKey();
    return DeviceIdentity(
      keyPair: keyPair,
      publicKeyBase64: base64.encode(publicKey.bytes),
    );
  }

  /// The roster of paired computers, in insertion order.
  Future<List<RosterComputer>> roster() async {
    final raw = await _storage.read(key: _kRoster);
    if (raw == null || raw.isEmpty) return <RosterComputer>[];
    final List<dynamic> decoded;
    try {
      decoded = json.decode(raw) as List<dynamic>;
    } on FormatException {
      return <RosterComputer>[];
    }
    return decoded
        .map((dynamic e) =>
            RosterComputer.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Adds (or updates) a computer, keyed by [fingerprint]. Updating keeps the
  /// existing name if the new one is empty (mDNS may not carry a name).
  Future<void> addComputer({
    required String name,
    required String fingerprint,
    required String lastAddr,
  }) async {
    final current = await roster();
    final existing = current.indexWhere((c) => c.fingerprint == fingerprint);
    final entry = RosterComputer(
      name: name.isEmpty && existing >= 0 ? current[existing].name : name,
      fingerprint: fingerprint,
      lastAddr: lastAddr,
    );
    if (existing >= 0) {
      current[existing] = entry;
    } else {
      current.add(entry);
    }
    await _writeRoster(current);
  }

  /// Removes one computer from the roster, keeping the device key. A no-op
  /// when [fingerprint] is not present.
  Future<void> removeComputer(String fingerprint) async {
    final current = await roster();
    current.removeWhere((c) => c.fingerprint == fingerprint);
    await _writeRoster(current);
  }

  /// Deletes the Ed25519 private key AND clears the roster: a full identity
  /// reset back to the pairing screen with a freshly generated key. The
  /// approval-sound preference is kept — it is a user setting, not identity.
  Future<void> resetIdentity() async {
    await _storage.delete(key: _kRoster);
    await _storage.delete(key: _kPrivateKey);
    _syncConfiguredFlag(false);
  }

  /// The approval-sound preference. Defaults to `true` when the key is
  /// missing or holds anything other than the explicit off marker `'0'`
  /// (a corrupt value falls back to on rather than silently muting).
  Future<bool> loadSoundEnabled() async {
    final raw = await _storage.read(key: _kSoundEnabled);
    return raw != '0';
  }

  /// Persists the approval-sound preference as `'1'`/`'0'`.
  Future<void> setSoundEnabled(bool enabled) async {
    await _storage.write(key: _kSoundEnabled, value: enabled ? '1' : '0');
  }

  Future<void> _writeRoster(List<RosterComputer> roster) async {
    await _storage.write(
      key: _kRoster,
      value: json.encode(
        roster.map((c) => c.toJson()).toList(),
      ),
    );
    _syncConfiguredFlag(roster.isNotEmpty);
  }

  /// Updates the native boot-receiver marker (see [_keepaliveChannel]).
  ///
  /// Fire-and-forget on purpose: the mirror must never block or break a
  /// roster write, and under flutter_test's FakeAsync an unhandled channel
  /// call never completes (the future hangs), so awaiting it here would
  /// deadlock pairing in widget tests. Errors are swallowed because the
  /// flag is self-correcting — every roster mutation rewrites it — and a
  /// stale value is harmless: the service's Dart `_bootstrap` waits for the
  /// identity instead of crashing, and the boot receiver is best-effort.
  void _syncConfiguredFlag(bool configured) {
    _keepaliveChannel
        .invokeMethod<void>(
          'setRosterConfigured',
          <String, dynamic>{'configured': configured},
        )
        .catchError((Object e) {
      // No native handler (tests / non-Android), no ServicesBinding (plain
      // unit tests), or the channel not yet attached on a cold engine start.
    });
  }
}
