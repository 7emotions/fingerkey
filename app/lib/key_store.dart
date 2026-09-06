/// Device identity: Ed25519 keypair persisted in Android Keystore-backed
/// secure storage, plus the daemon base URL setting.
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class DeviceIdentity {
  const DeviceIdentity({required this.keyPair, required this.publicKeyBase64});

  final SimpleKeyPair keyPair;

  /// Standard (padded) base64 of the raw 32-byte Ed25519 public key.
  /// This is the string the daemon operator registers during pairing.
  final String publicKeyBase64;
}

class KeyStore {
  static const String _kPrivateKey = 'ed25519_private_key';
  static const String _kDaemonUrl = 'daemon_url';
  static const String defaultDaemonUrl = 'http://192.168.1.100:8766';

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

  Future<String> daemonUrl() async =>
      await _storage.read(key: _kDaemonUrl) ?? defaultDaemonUrl;

  Future<void> setDaemonUrl(String url) =>
      _storage.write(key: _kDaemonUrl, value: url.trim());
}
