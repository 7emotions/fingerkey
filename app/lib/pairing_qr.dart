/// Parsing and validation of the pairing QR printed by the computer-side
/// `phone-approve pair-qr` command.
///
/// The QR encodes a JSON object with exactly two keys:
/// - `url`: the `https://` daemon base URL (e.g. `https://192.168.112.239:8766`)
/// - `pin`: the 64-lowercase-hex SHA-256 fingerprint of the daemon TLS cert
///
/// This file is pure Dart (no Flutter imports) so the parser is unit-testable
/// without a device or camera. The JSON shape must stay in lock-step with the
/// computer-side encoder.
library;

import 'dart:convert';

import 'key_store.dart';

/// A validated daemon URL + certificate fingerprint taken from a pairing QR.
class PairingInfo {
  const PairingInfo({required this.url, required this.pin});

  final String url;
  final String pin;
}

/// Parses a scanned QR payload into [PairingInfo].
///
/// Returns null when the payload is not a phone-fprint-auth pairing QR:
/// unparseable JSON, a non-object shape, missing/wrong-typed `url` or `pin`,
/// a non-`https://` URL, or a pin that is not 64-lowercase-hex.
PairingInfo? parsePairingQr(String raw) {
  final Object? decoded;
  try {
    decoded = json.decode(raw);
  } on FormatException {
    return null;
  }
  if (decoded is! Map<String, dynamic>) return null;

  final url = decoded['url'];
  final pin = decoded['pin'];
  if (url is! String || pin is! String) return null;

  final trimmedUrl = url.trim();
  if (!KeyStore.isHttpsUrl(trimmedUrl)) return null;
  if (!KeyStore.isHexPin(pin)) return null;

  return PairingInfo(url: trimmedUrl, pin: pin);
}
