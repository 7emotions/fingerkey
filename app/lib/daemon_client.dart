/// HTTP client for the phone-fprint-auth LAN daemon (default
/// http://192.168.1.100:8766).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

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
  DaemonClient({required this.baseUrl, http.Client? client})
      : _client = client ?? http.Client();

  final String baseUrl;
  final http.Client _client;

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
