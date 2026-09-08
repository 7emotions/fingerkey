/// Device identity: Ed25519 keypair persisted in Android Keystore-backed
/// secure storage, plus the daemon base URL and TLS certificate pin.
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'daemon_client.dart';

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
  static const String _kCertPin = 'daemon_cert_pin';
  static const String defaultDaemonUrl = 'https://192.168.112.239:8766';

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

  /// The raw stored daemon URL (null when never configured). Callers that
  /// must distinguish "unset" from "leftover non-https" (e.g. pairing
  /// re-entry) use this instead of [daemonUrl].
  Future<String?> daemonUrlStored() async => await _storage.read(key: _kDaemonUrl);

  Future<String> daemonUrl() async =>
      effectiveDaemonUrl(await _storage.read(key: _kDaemonUrl));

  Future<void> setDaemonUrl(String url) =>
      _storage.write(key: _kDaemonUrl, value: url.trim());

  /// 64-lowercase-hex SHA-256 fingerprint of the daemon's TLS leaf
  /// certificate (SHA-256 of the DER encoding). Entered at pairing.
  Future<String?> certPin() async => await _storage.read(key: _kCertPin);

  Future<void> setCertPin(String pin) =>
      _storage.write(key: _kCertPin, value: pin);

  /// True when [url] parses as an `https://` URL.
  static bool isHttpsUrl(String url) {
    final uri = Uri.tryParse(url.trim());
    return uri != null && uri.scheme == 'https';
  }

  /// The daemon URL to use given a stored value.
  ///
  /// A stored non-`https` URL (e.g. a leftover `http://` from before the
  /// TLS hardening) is NOT silently kept — it is treated as unset so the
  /// user must re-enter it at pairing.
  static String effectiveDaemonUrl(String? stored) {
    if (stored == null || !isHttpsUrl(stored)) return defaultDaemonUrl;
    return stored.trim();
  }

  /// True when pairing (re-entry) is required: no URL stored, no VALID pin
  /// stored (a corrupt non-empty pin must not silently disable pinning), or
  /// the stored URL is not `https://`.
  static bool needsPairing(String? storedUrl, String? pin) {
    if (storedUrl == null || pin == null || !DaemonClient.isHexPin(pin)) {
      return true;
    }
    return !isHttpsUrl(storedUrl);
  }
}
