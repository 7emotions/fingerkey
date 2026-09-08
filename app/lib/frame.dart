/// Wire framing for the daemon-facing stream, mirroring daemon/frame.go:
/// every frame is a 4-byte big-endian uint32 length prefix followed by
/// exactly that many bytes of UTF-8 JSON.
///
/// This file is pure Dart (no Flutter imports) so the codec is unit-testable
/// without a device. Keep it in sync with the Go side.
library;

import 'dart:typed_data';

/// Maximum frame payload size — mirrors Go's `maxFrameSize` (1 MiB).
const int kMaxFrameSize = 1 << 20;

/// Thrown by [FrameDecoder] when a frame declares a length beyond
/// [kMaxFrameSize] — mirrors Go's `errFrameTooLarge`.
class FrameTooLargeException implements Exception {
  const FrameTooLargeException(this.declaredLength);

  final int declaredLength;

  @override
  String toString() => 'FrameTooLargeException: declared length '
      '$declaredLength exceeds $kMaxFrameSize';
}

/// Encodes [payload] as one wire frame: the 4-byte big-endian uint32 length
/// prefix followed by the payload bytes (mirrors Go's `writeFrame`).
Uint8List encodeFrame(Uint8List payload) {
  final out = Uint8List(4 + payload.length);
  ByteData.sublistView(out).setUint32(0, payload.length, Endian.big);
  out.setRange(4, out.length, payload);
  return out;
}

/// Streaming frame decoder: feed received chunks with [add] and collect the
/// complete frames it contains, in order (mirrors Go's `readFrame`).
class FrameDecoder {
  Uint8List _pending = Uint8List(0);

  /// Feeds a received chunk into the decoder and returns the complete frames
  /// it contains. Throws [FrameTooLargeException] when a declared length
  /// exceeds [kMaxFrameSize] (no payload is allocated in that case).
  List<Uint8List> add(Uint8List bytes) {
    if (_pending.isEmpty) {
      _pending = bytes;
    } else {
      final combined = Uint8List(_pending.length + bytes.length);
      combined.setRange(0, _pending.length, _pending);
      combined.setRange(_pending.length, combined.length, bytes);
      _pending = combined;
    }
    final frames = <Uint8List>[];
    while (_pending.length >= 4) {
      final n = ByteData.sublistView(_pending).getUint32(0, Endian.big);
      if (n > kMaxFrameSize) throw FrameTooLargeException(n);
      if (_pending.length < 4 + n) break;
      frames.add(Uint8List.sublistView(_pending, 4, 4 + n));
      _pending = Uint8List.sublistView(_pending, 4 + n);
    }
    return frames;
  }
}
