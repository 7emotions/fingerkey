/// HTTP client for the phone-fprint-auth LAN daemon (HTTPS with an optional
/// self-signed-certificate SHA-256 pin).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

class PendingSession {
  PendingSession({
    required this.id,
    required this.nonce,
    required this.user,
    required this.service,
    required this.tty,
  });

  factory PendingSession.fromJson(Map<String, dynamic> json) => PendingSession(
        id: json['id'] as String,
        // nonce is base64 (std, padded) of 32 raw bytes.
        nonce: base64.decode(json['nonce'] as String),
        user: json['user'] as String? ?? '',
        service: json['service'] as String? ?? '',
        tty: json['tty'] as String? ?? '',
      );

  final String id;
  final Uint8List nonce;
  final String user;
  final String service;
  final String tty;
}

class DaemonHttpException implements Exception {
  const DaemonHttpException(this.statusCode, this.body);

  final int statusCode;
  final String body;

  @override
  String toString() => 'DaemonHttpException($statusCode): $body';
}

class DaemonClient {
  /// [pin] is the daemon TLS leaf certificate fingerprint: 64 lowercase hex
  /// (SHA-256 of the DER-encoded certificate). When set, the connection is
  /// pinned to that exact certificate regardless of hostname, so DHCP IP
  /// changes do not break pairing. [baseUrl] must be an `https://` URL.
  DaemonClient({required this.baseUrl, String? pin, http.Client? client})
      : _client = client ?? _pinnedClient(pin);

  final String baseUrl;
  final http.Client _client;

  /// Builds the client: an [IOClient] whose [HttpClient] pins the leaf
  /// certificate by SHA-256 when [pin] is present, or a plain client.
  ///
  /// A non-null [pin] that is not a valid 64-lowercase-hex fingerprint
  /// throws [ArgumentError]: pinning is never silently downgraded to an
  /// unpinned connection.
  static http.Client _pinnedClient(String? pin) {
    if (pin == null) return http.Client();
    final pinBytes = decodeHexPin(pin);
    if (pinBytes == null) {
      throw ArgumentError.value(
          pin, 'pin', 'must be a 64-lowercase-hex SHA-256 fingerprint');
    }
    final inner = HttpClient()
      ..badCertificateCallback = (X509Certificate cert, String host, int port) =>
          _bytesEqual(sha256.convert(cert.der).bytes, pinBytes);
    return IOClient(inner);
  }

  /// Decodes a 64-character lowercase-hex fingerprint into 32 raw bytes
  /// (the SHA-256 digest). Returns null on malformed input.
  static Uint8List? decodeHexPin(String pin) {
    if (pin.length != 64) return null;
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      final hi = _hexNibble(pin.codeUnitAt(i * 2));
      final lo = _hexNibble(pin.codeUnitAt(i * 2 + 1));
      if (hi < 0 || lo < 0) return null;
      bytes[i] = (hi << 4) | lo;
    }
    return bytes;
  }

  /// True when [pin] is a valid 64-lowercase-hex fingerprint.
  static bool isHexPin(String pin) => decodeHexPin(pin) != null;

  static int _hexNibble(int codeUnit) {
    if (codeUnit >= 0x30 && codeUnit <= 0x39) return codeUnit - 0x30; // 0-9
    if (codeUnit >= 0x61 && codeUnit <= 0x66) return codeUnit - 0x61 + 10; // a-f
    return -1;
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Long-polls `GET /v1/pending?wait=<waitSeconds>`.
  ///
  /// Returns null on 204 (timeout — caller should poll again) and throws
  /// [DaemonHttpException] on any other non-200 status.
  Future<PendingSession?> pollPending({int waitSeconds = 60}) async {
    final uri = Uri.parse('$baseUrl/v1/pending?wait=$waitSeconds');
    final response = await _client
        .get(uri)
        .timeout(Duration(seconds: waitSeconds + 15));
    if (response.statusCode == 204) return null;
    if (response.statusCode != 200) {
      throw DaemonHttpException(response.statusCode, response.body);
    }
    return PendingSession.fromJson(
        json.decode(response.body) as Map<String, dynamic>);
  }

  /// `POST /v1/session/{id}/decision` with a signed decision.
  ///
  /// Returns the HTTP status code (200 = recorded, 401 = bad signature).
  Future<int> postDecision({
    required String sessionId,
    required String decision,
    required String signatureBase64,
  }) async {
    final uri = Uri.parse('$baseUrl/v1/session/$sessionId/decision');
    final response = await _client
        .post(
          uri,
          headers: const {'Content-Type': 'application/json'},
          body: json.encode({'decision': decision, 'sig': signatureBase64}),
        )
        .timeout(const Duration(seconds: 15));
    return response.statusCode;
  }

  void close() => _client.close();
}
