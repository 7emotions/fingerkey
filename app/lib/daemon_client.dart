/// Framed Bluetooth SPP client for the phone-fprint-auth daemon.
///
/// Wire protocol (see daemon/phone_link.go): every frame is a 4-byte
/// big-endian length prefix followed by UTF-8 JSON (see frame.dart). The
/// daemon pushes `{"type":"pending",...}` frames over the link; the phone
/// answers with `{"type":"decision",...}` frames and reads the daemon's
/// `{"type":"decision-result",...}` reply.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'bt_link.dart';
import 'frame.dart';

/// A pending sudo/pkexec approval request pushed by the daemon.
class PendingSession {
  PendingSession({
    required this.id,
    required this.nonce,
    required this.user,
    required this.service,
    required this.tty,
  });

  /// Parses a daemon→phone `pending` frame
  /// (`{"type":"pending","id":...,"nonce":...,"user":...,"service":...,
  /// "tty":...}`).
  factory PendingSession.fromFrameJson(Map<String, dynamic> json) =>
      PendingSession(
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

/// The daemon's answer to a posted decision. On success [status] is
/// `approved` or `denied` (and [key] names the paired key that signed it);
/// on failure [error] carries the reason (e.g. `invalid-signature`,
/// `unknown-session`).
class DecisionResult {
  const DecisionResult({this.status, this.key, this.error});

  /// Parses a daemon→phone `decision-result` frame.
  factory DecisionResult.fromFrameJson(Map<String, dynamic> json) =>
      DecisionResult(
        status: json['status'] as String?,
        key: json['key'] as String?,
        error: json['error'] as String?,
      );

  final String? status;
  final String? key;
  final String? error;

  /// True when the daemon rejected the decision.
  bool get isError => error != null;
}

/// Framed SPP client: consumes the daemon's push stream and posts signed
/// decisions over the shared [BtLink].
class BtClient {
  /// [link] is injectable for tests; defaults to the real platform channel.
  BtClient({BtLink? link}) : _link = link ?? BtLink();

  /// How long [postDecision] waits for the matching `decision-result` frame.
  static const Duration decisionTimeout = Duration(seconds: 15);

  final BtLink _link;

  /// The stream of pending approval requests pushed by the daemon.
  ///
  /// Each `data` event's bytes are fed to a [FrameDecoder]; every complete
  /// frame whose JSON `type` is `pending` is yielded as a [PendingSession].
  Stream<PendingSession> pending() {
    final decoder = FrameDecoder();
    return _link.events.asyncExpand((BtEvent event) async* {
      if (event.status != 'data' || event.data == null) return;
      final List<Uint8List> frames;
      try {
        frames = decoder.add(event.data!);
      } on FrameTooLargeException {
        return; // Malformed/oversized frame; drop this chunk's bytes.
      }
      for (final frame in frames) {
        final session = _parsePending(frame);
        if (session != null) yield session;
      }
    });
  }

  /// Sends a signed `decision` frame and awaits the matching
  /// `decision-result` frame (matched by session id).
  ///
  /// The subscription is taken before the frame is sent so the reply can
  /// never be missed. Throws [TimeoutException] when the daemon does not
  /// answer within [decisionTimeout].
  Future<DecisionResult> postDecision({
    required String sessionId,
    required String decision,
    required String signatureBase64,
  }) async {
    final decoder = FrameDecoder();
    final result = Completer<DecisionResult>();
    final sub = _link.events.listen(
      (BtEvent event) {
        if (event.status != 'data' || event.data == null) return;
        final List<Uint8List> frames;
        try {
          frames = decoder.add(event.data!);
        } on FrameTooLargeException {
          return;
        }
        for (final frame in frames) {
          if (result.isCompleted) return;
          final parsed = _parseDecisionResult(frame);
          if (parsed != null && parsed.id == sessionId) {
            result.complete(parsed.result);
          }
        }
      },
      onError: (Object e, StackTrace st) {
        if (!result.isCompleted) result.completeError(e, st);
      },
    );
    try {
      final payload = json.encode(<String, dynamic>{
        'type': 'decision',
        'id': sessionId,
        'decision': decision,
        'sig': signatureBase64,
      });
      await _link
          .send(encodeFrame(Uint8List.fromList(utf8.encode(payload))));
      return await result.future.timeout(decisionTimeout);
    } finally {
      await sub.cancel();
    }
  }

  /// Releases the client. Dart-side subscriptions are owned by callers and
  /// the platform channel holds no per-client resources, so this is
  /// currently a no-op lifecycle hook.
  void dispose() {}

  static PendingSession? _parsePending(Uint8List frame) {
    final json = _decodeFrameJson(frame);
    if (json == null || json['type'] != 'pending') return null;
    return PendingSession.fromFrameJson(json);
  }

  static _DecisionResultFrame? _parseDecisionResult(Uint8List frame) {
    final json = _decodeFrameJson(frame);
    if (json == null || json['type'] != 'decision-result') return null;
    return _DecisionResultFrame(
      id: json['id'] as String? ?? '',
      result: DecisionResult.fromFrameJson(json),
    );
  }

  static Map<String, dynamic>? _decodeFrameJson(Uint8List frame) {
    final Object? decoded;
    try {
      decoded = json.decode(utf8.decode(frame));
    } on FormatException {
      return null;
    }
    if (decoded is! Map<String, dynamic>) return null;
    return decoded;
  }
}

/// A parsed `decision-result` frame: its session id plus the result body.
class _DecisionResultFrame {
  const _DecisionResultFrame({required this.id, required this.result});

  final String id;
  final DecisionResult result;
}
