/// Tests for lib/pairing_qr.dart.
///
/// Canonical location per the build plan is lib/pairing_qr_test.dart; the
/// test/pairing_qr_test.dart delegator makes `flutter test` discover these.
library;

// Test-only file pinned at lib/ per the build plan; the runner entry point
// is test/pairing_qr_test.dart.
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';

import 'package:auth/pairing_qr.dart';

/// 64 lowercase hex chars (valid pin).
const _hex64 =
    '3c39e582a040d31dcdb5b3da2e0bc965fb9b050efc02495ec3b1d6570a2b03a3';

String _qr(String url, String pin) =>
    '{"url":"$url","pin":"$pin"}';

void main() {
  group('parsePairingQr valid input', () {
    test('accepts the canonical pairing QR and fills url + pin', () {
      final info = parsePairingQr(_qr('https://x:8766', _hex64));
      expect(info, isNotNull);
      expect(info!.url, 'https://x:8766');
      expect(info.pin, _hex64);
    });

    test('accepts the task-pinned vector (daemon at 192.168.112.239)', () {
      final info = parsePairingQr(
          _qr('https://192.168.112.239:8766', _hex64));
      expect(info, isNotNull);
      expect(info!.url, 'https://192.168.112.239:8766');
      expect(info.pin, _hex64);
    });

    test('trims surrounding whitespace from the url', () {
      final info = parsePairingQr(
          _qr('  https://x:8766  ', _hex64));
      expect(info, isNotNull);
      expect(info!.url, 'https://x:8766');
    });
  });

  group('parsePairingQr rejects malformed input', () {
    test('non-https url (http) → null', () {
      expect(parsePairingQr(_qr('http://x:8766', _hex64)), isNull);
    });

    test('url without scheme → null', () {
      expect(parsePairingQr(_qr('192.168.112.239:8766', _hex64)), isNull);
    });

    test('empty url → null', () {
      expect(parsePairingQr(_qr('', _hex64)), isNull);
    });

    test('pin shorter than 64 hex → null', () {
      expect(parsePairingQr(_qr('https://x:8766', _hex64.substring(1))),
          isNull);
    });

    test('pin with uppercase hex → null (must be lowercase)', () {
      expect(parsePairingQr(_qr('https://x:8766', _hex64.toUpperCase())),
          isNull);
    });

    test('pin with non-hex characters → null', () {
      expect(
          parsePairingQr(
              _qr('https://x:8766', 'z3c9e582a040d31dcdb5b3da2e0bc965fb9b050'
                  'efc02495ec3b1d6570a2b03a3')),
          isNull);
    });

    test('pin with surrounding whitespace → null', () {
      expect(parsePairingQr(_qr('https://x:8766', ' $_hex64 ')), isNull);
    });

    test('missing pin key → null', () {
      expect(parsePairingQr('{"url":"https://x:8766"}'), isNull);
    });

    test('missing url key → null', () {
      expect(parsePairingQr('{"pin":"$_hex64"}'), isNull);
    });

    test('wrong value types → null', () {
      expect(parsePairingQr('{"url":123,"pin":"$_hex64"}'), isNull);
      expect(parsePairingQr('{"url":"https://x:8766","pin":[]}'), isNull);
      expect(parsePairingQr('[1,2,3]'), isNull);
      expect(parsePairingQr('"just a string"'), isNull);
    });

    test('not JSON at all → null', () {
      expect(parsePairingQr('this is not json'), isNull);
      expect(parsePairingQr(''), isNull);
      expect(parsePairingQr('https://x:8766'), isNull);
    });
  });
}
