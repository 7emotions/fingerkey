/// Tests for lib/format.dart.
///
/// Canonical location per the build plan is lib/format_test.dart; the
/// test/format_test.dart delegator makes `flutter test` discover these.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:auth/format.dart';
import 'package:cryptography/cryptography.dart';
// Test-only file pinned at lib/ per the build plan; the runner entry point
// is test/format_test.dart.
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final nonce42 = Uint8List.fromList(List.filled(32, 0x42));

  group('signedMessage byte layout (must match Go daemon)', () {
    test('task-pinned vector: approve/alice/sudo/"" + 32x0x42', () {
      // Expected: "phone-fprint-auth/v1\x00approve\x00\x05alice\x04sudo\x00"
      // followed by the raw nonce.
      final got = signedMessage(kActionApprove, 'alice', 'sudo', '', nonce42);
      final expected = <int>[
        ...utf8.encode(
            'phone-fprint-auth/v1\x00approve\x00\x05alice\x04sudo\x00'),
        ...nonce42,
      ];
      expect(got, equals(expected));
    });

    test('approve with tty (mirrors daemon TestSignedMessageLayout)', () {
      final got =
          signedMessage(kActionApprove, 'alice', 'sudo', '/dev/pts/0', nonce42);
      final expected = <int>[
        ...utf8.encode('phone-fprint-auth/v1'),
        0x00,
        ...utf8.encode('approve'),
        0x00,
        0x05, ...utf8.encode('alice'),
        0x04, ...utf8.encode('sudo'),
        0x0A, ...utf8.encode('/dev/pts/0'),
        ...nonce42, // raw 32 bytes, no length prefix
      ];
      expect(got, equals(expected));
    });

    test('empty tty still contributes its zero length byte', () {
      final got = signedMessage(kActionDeny, 'bob', 'su', '', Uint8List(32));
      final expected = <int>[
        ...utf8.encode('phone-fprint-auth/v1'),
        0x00,
        ...utf8.encode('deny'),
        0x00,
        0x03, ...utf8.encode('bob'),
        0x02, ...utf8.encode('su'),
        0x00, // u8len(tty) == 0, zero bytes follow
        ...Uint8List(32),
      ];
      expect(got, equals(expected));
    });
  });

  group('Ed25519 interop', () {
    test('public key derived from seed matches RFC 8032 TEST 1', () async {
      // Go's crypto/ed25519 derives the same public key from the same seed;
      // this vector proves `cryptography` is wire-compatible with the daemon.
      final seed = Uint8List.fromList(base64
          .decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=')); // 9d61..7f60
      expect(_hex(seed),
          '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
      final keyPair = await Ed25519().newKeyPairFromSeed(seed);
      final publicKey = await keyPair.extractPublicKey();
      expect(_hex(publicKey.bytes),
          'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    });
  });

  group('signDecision', () {
    test('produces a padded std-base64 signature that verifies', () async {
      final keyPair = await Ed25519().newKeyPair();
      final publicKey = await keyPair.extractPublicKey();

      final sigB64 = await signDecision(
        keyPair: keyPair,
        action: kActionApprove,
        user: 'alice',
        service: 'sudo',
        tty: '',
        nonce: nonce42,
      );

      final sigBytes = base64.decode(sigB64); // throws unless std padded b64
      expect(sigBytes.length, 64);

      final valid = await Ed25519().verify(
        signedMessage(kActionApprove, 'alice', 'sudo', '', nonce42),
        signature: Signature(sigBytes, publicKey: publicKey),
      );
      expect(valid, isTrue);
    });

    test('a deny signature does not verify as approve (action binding)',
        () async {
      final keyPair = await Ed25519().newKeyPair();
      final publicKey = await keyPair.extractPublicKey();

      final sigB64 = await signDecision(
        keyPair: keyPair,
        action: kActionDeny,
        user: 'alice',
        service: 'sudo',
        tty: '',
        nonce: nonce42,
      );

      final valid = await Ed25519().verify(
        signedMessage(kActionApprove, 'alice', 'sudo', '', nonce42),
        signature: Signature(base64.decode(sigB64), publicKey: publicKey),
      );
      expect(valid, isFalse);
    });

    test('a signature over user alice does not verify for bob', () async {
      final keyPair = await Ed25519().newKeyPair();
      final publicKey = await keyPair.extractPublicKey();

      final sigB64 = await signDecision(
        keyPair: keyPair,
        action: kActionApprove,
        user: 'alice',
        service: 'sudo',
        tty: '',
        nonce: nonce42,
      );

      final valid = await Ed25519().verify(
        signedMessage(kActionApprove, 'bob', 'sudo', '', nonce42),
        signature: Signature(base64.decode(sigB64), publicKey: publicKey),
      );
      expect(valid, isFalse);
    });
  });
}
