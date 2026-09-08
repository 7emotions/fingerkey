/// Device identity: Ed25519 keypair persisted in Android Keystore-backed
/// secure storage, plus the paired daemon's Bluetooth address.
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
  static const String _kBtAddress = 'bt_address';

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

  /// The MAC address of the paired daemon computer (null when never paired).
  /// The phone dials the daemon's SPP server at this address.
  Future<String?> btAddress() async => await _storage.read(key: _kBtAddress);

  Future<void> setBtAddress(String address) =>
      _storage.write(key: _kBtAddress, value: address.trim());

  /// Wipes the pairing state: the paired Bluetooth address and the Ed25519
  /// private key. Used by the re-pair flow so that a fresh identity is
  /// generated on the next pairing instead of reusing a stale one.
  Future<void> clear() async {
    await _storage.delete(key: _kBtAddress);
    await _storage.delete(key: _kPrivateKey);
  }
}
