/// Tests for lib/frame.dart — the pure-Dart mirror of daemon/frame.go.
///
/// The wire contract: every frame is a 4-byte big-endian uint32 length
/// prefix followed by exactly that many payload bytes; a declared length
/// beyond 1 MiB is rejected without allocating the payload.
library;

import 'dart:typed_data';

import 'package:auth/frame.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List _payload(int size) {
  final p = Uint8List(size);
  for (var i = 0; i < size; i++) {
    p[i] = (i * 7 + 13) & 0xff;
  }
  return p;
}

void main() {
  group('encodeFrame', () {
    test('prefixes a 4-byte big-endian uint32 length', () {
      expect(encodeFrame(Uint8List.fromList([1, 2, 3])), [0, 0, 0, 3, 1, 2, 3]);
    });

    test('empty payload yields a zero-length frame', () {
      expect(encodeFrame(Uint8List(0)), [0, 0, 0, 0]);
    });
  });

  group('FrameDecoder round-trip', () {
    test('200-byte frame round-trips byte-identical in one chunk', () {
      final payload = _payload(200);
      final decoded = FrameDecoder().add(encodeFrame(payload));
      expect(decoded, hasLength(1));
      expect(decoded.single, payload);
    });

    test('frame fed one byte at a time is still decoded', () {
      final payload = _payload(200);
      final frame = encodeFrame(payload);
      final decoder = FrameDecoder();
      var decoded = const <Uint8List>[];
      for (var i = 0; i < frame.length; i++) {
        decoded = decoder.add(frame.sublist(i, i + 1));
      }
      expect(decoded, hasLength(1));
      expect(decoded.single, payload);
    });

    test('frame split across chunk boundaries is reassembled', () {
      final payload = _payload(300);
      final frame = encodeFrame(payload);
      final decoder = FrameDecoder();
      expect(decoder.add(frame.sublist(0, 2)), isEmpty); // header split
      expect(decoder.add(frame.sublist(2, 10)), isEmpty); // partial payload
      final decoded = decoder.add(frame.sublist(10));
      expect(decoded, hasLength(1));
      expect(decoded.single, payload);
    });

    test('two frames in one chunk are both yielded in order', () {
      final a = _payload(7);
      final b = _payload(13);
      final fa = encodeFrame(a);
      final fb = encodeFrame(b);
      final chunk = Uint8List(fa.length + fb.length);
      chunk
        ..setRange(0, fa.length, fa)
        ..setRange(fa.length, chunk.length, fb);
      final decoded = FrameDecoder().add(chunk);
      expect(decoded, hasLength(2));
      expect(decoded[0], a);
      expect(decoded[1], b);
    });

    test('incomplete frame yields nothing yet', () {
      expect(FrameDecoder().add(Uint8List.fromList([0, 0])), isEmpty);
      expect(
        FrameDecoder().add(Uint8List.fromList([0, 0, 0, 10, 1, 2, 3])),
        isEmpty,
      );
    });

    test('a frame at exactly kMaxFrameSize is accepted', () {
      final payload = Uint8List(kMaxFrameSize);
      final decoded = FrameDecoder().add(encodeFrame(payload));
      expect(decoded, hasLength(1));
      expect(decoded.single, payload);
    });
  });

  group('oversized frames', () {
    test('declared length just above kMaxFrameSize throws', () {
      final decoder = FrameDecoder();
      final header = Uint8List(4);
      ByteData.sublistView(header)
          .setUint32(0, kMaxFrameSize + 1, Endian.big);
      expect(
        () => decoder.add(header),
        throwsA(isA<FrameTooLargeException>()),
      );
    });

    test('2 MiB declared length throws FrameTooLargeException', () {
      final decoder = FrameDecoder();
      final header = Uint8List(4);
      ByteData.sublistView(header).setUint32(0, 2 << 20, Endian.big);
      expect(
        () => decoder.add(header),
        throwsA(isA<FrameTooLargeException>()),
      );
    });
  });
}
