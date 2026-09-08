/// Tests for TLS certificate pinning: hex pin parsing, the pinned
/// DaemonClient against a local HTTPS server with a known self-signed cert,
/// and the https-only URL rules.
///
/// Canonical location per the build plan is lib/tls_pin_test.dart; the
/// test/tls_pin_test.dart delegator makes `flutter test` discover these.
library;

import 'dart:convert';
import 'dart:io';

import 'package:auth/daemon_client.dart';
import 'package:auth/key_store.dart';
import 'package:crypto/crypto.dart';
// Test-only file pinned at lib/ per the build plan; the runner entry point
// is test/tls_pin_test.dart.
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';

/// Self-signed test certificate (CN=pin-test-localhost, SAN IP:127.0.0.1),
/// generated solely for this test suite. It is NOT the production daemon
/// certificate and its fingerprint must never become a build-time default.
const String _testCertPem = '''
-----BEGIN CERTIFICATE-----
MIIDLDCCAhSgAwIBAgIUVDNchfGx8DPtOjb5kMXIjF2oSdkwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwScGluLXRlc3QtbG9jYWxob3N0MB4XDTI2MDkwODA1NDM0
M1oXDTM2MDkwNTA1NDM0M1owHTEbMBkGA1UEAwwScGluLXRlc3QtbG9jYWxob3N0
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiNWZX78n1483Qa4JWt/P
kKPVBuzef/E9ktaWxbwEOCStAudO3Fpp/B67jMaOFvoESbdzHpEFI50nULntee8O
hpEZk4/DMfrBKSvdoMZqOSgOgIK51pH9ndkNgQxoTO5wyHaI5lb/FkQ7cqkYZuSu
qoguAPvneKBU+hv4Jw3kc25v0Us50AH9dzYumMmbkPhsyV/k0feIWMCuRjAvPuvM
PBGjq/ty0UvlMIlJL4Dy5vu3IC7124fMmP8UdZYk7CtrC9hth4ZOT+6kDUjfJ4G5
RyQdb7TnatbsdPGE5VjaNhgNTdrg9uIUCNTojhOPae7NpJITsL/gBCuIwqAK0uma
PwIDAQABo2QwYjAdBgNVHQ4EFgQUJvJGOcGgCDEtZwl/6T4Ax4ohlYAwHwYDVR0j
BBgwFoAUJvJGOcGgCDEtZwl/6T4Ax4ohlYAwDwYDVR0TAQH/BAUwAwEB/zAPBgNV
HREECDAGhwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQA4GxFk67a1dFCoyTtzxvuq
15c0beD4mAdXTrGlArgAtn18CWiEf9V7v4bKTzXkEaVA3wHNYmS3MAXH+OmFh883
YDEWyyIXX3dkYqZyFQuAoMWUTZj/9YjgVwSEUqSYTWXgzcFKVIzeAHMyk2gf9PG7
kpoNxxHGG9ef4vZhbVC3g/6765vYeFQtcnWkeScVf0F3Ex3UXioQvdXDwKX3ubeW
+D4XANgY35zd29ytyfty6Z7hNeinMU8lKS6w1BUET5/pBfL1dJ16GQu1gm6/ERDu
ES6EJNTkWOpUp/W6R0JtSD84U02CXgnrW/4FRN25fhuxtGpAnR02vdoIbKTTaBI2
-----END CERTIFICATE-----
''';

const String _testKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCI1ZlfvyfXjzdB
rgla38+Qo9UG7N5/8T2S1pbFvAQ4JK0C507cWmn8HruMxo4W+gRJt3MekQUjnSdQ
ue157w6GkRmTj8Mx+sEpK92gxmo5KA6AgrnWkf2d2Q2BDGhM7nDIdojmVv8WRDty
qRhm5K6qiC4A++d4oFT6G/gnDeRzbm/RSznQAf13Ni6YyZuQ+GzJX+TR94hYwK5G
MC8+68w8EaOr+3LRS+UwiUkvgPLm+7cgLvXbh8yY/xR1liTsK2sL2G2Hhk5P7qQN
SN8ngblHJB1vtOdq1ux08YTlWNo2GA1N2uD24hQI1OiOE49p7s2kkhOwv+AEK4jC
oArS6Zo/AgMBAAECggEAHmlGoKqF6tkoIT9SUfGbGpzm3Bap7sqJckiiEslSML4p
+5K4Cq5HjuKvsT5x1vZzHIUan0kA2OT1F3JzLp3sXwkBo7OYYNPHuWRH6hMfCZv2
+SXUsrUYpkvWvf8pcSuvQkZh77uXDvZUNgwR4dBiZ4FDpDFYRQ1xRXMQ6HEkfGjU
XEpURqweXVhbJAvNqmMl0tKQcQm3SkSoRJaGrjIKOjNzz2PdcQMz/L/A1u7tH9nj
AQS2ygQNaumIxykmP0asnEGiC02ZyBu3k1hZrQBYLPD6XEXC1lNdvCwqdRfVQuAH
EsKMGyleadFhyZ1k+F2BiyKE1rP9fYeMdVY/Y2gysQKBgQC6XxE9Gq3XeKXGtQqq
OCMZlb3p/PrN9MvjKjU1kPmHLngvbes3RgULUcjEDDC/uJYSf4tMPEAakvtc3ZU1
ec5iX+aeXpMoiLJqHXJKKLDSLUEa0GS+2XtvuPAEynZdkoMrthISqUKope4HtfDs
jxg5zRt3xxgmFPgd3UKte1q8cQKBgQC79LbsY6EqMhVm6DhKfy2avFJQHdzHQZZ0
a9bsNCjwyCVE6ePSUeypNCGE7HsgtEfETPvKed9v4u8h8P24eJPsznWIziRZdwc5
K9WdbzH4fMGwpzzXO/89XT9vZ0pRft6WDlJ2M3GtXM6B8+SeV5Lr0JKQU41gduua
Z8F7KBfZrwKBgD/O6LII/lf1YJylw18AFVRfJkSEbsIw+9Vs0Abk+enEiTWD5rJn
8LYtbBVjLxWU9xyiOmkBf9kZVaI34ywJ5hVcTDMQokWQd7VJG6Y0REXRZKbvjm6h
O1fG87ZQMzJaRTqj/ZASD1Z6aQKO0kvLujmf9bWOnr/7Ee/3nyqSP0ChAoGAfb6h
ZpLc7sLlCJzRlB1zoDLfitP/sZrSkn7XId1fin8MWAd2MG44u5ax2iDv2xhhbxXl
2jcg4dTcEUQOKo0YwfP6NBVdwjDct0X5OsN6lfi5CHtKO+DayO4Kk3hyAwWy2oco
agXOxqHxUoWd7MU/+N3oQAB19BR7WSiTC9bt5ecCgYAFQpuH3zG8qJf1NpVsK2HM
9KwzLUTn9w2cKoDEDfc4HZcwYEWg4L4ii47WYduQweNKhVPY2rk6b8xaC5NiQLp1
miMOM7Vmfnkex4O/XDAmv1NkmDERg9uIjukvGIMjuJ3LexBvy1f5lTjUf2laKIX1
xoW5sUpWfiul9QfgH41ASg==
-----END PRIVATE KEY-----
''';

/// SHA-256 of the DER encoding of the test certificate above
/// (`openssl x509 -in cert.pem -outform DER | sha256sum`).
const String _testCertFingerprint =
    'ad17f3c79381677ca19096a31a910ea4f142004b54465419cd4780f941a757a6';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Binds an HTTPS loopback server presenting the embedded self-signed cert,
/// answering every request with 204, and returns its https URL.
Future<HttpServer> _startTlsServer() async {
  final context = SecurityContext()
    ..useCertificateChainBytes(utf8.encode(_testCertPem))
    ..usePrivateKeyBytes(utf8.encode(_testKeyPem));
  final server =
      await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, context);
  server.listen((request) {
    request.response.statusCode = HttpStatus.noContent;
    request.response.close();
  });
  return server;
}

void main() {
  group('pin hex parsing', () {
    test('64 lowercase hex parses to 32 bytes', () {
      final bytes = DaemonClient.decodeHexPin(_testCertFingerprint);
      expect(bytes, isNotNull);
      expect(bytes!.length, 32);
      expect(bytes.first, 0xad);
      expect(bytes.last, 0xa6);
      expect(_hex(bytes), _testCertFingerprint);
    });

    test('malformed pins are rejected', () {
      expect(DaemonClient.decodeHexPin(''), isNull);
      expect(DaemonClient.decodeHexPin('abcd'), isNull);
      expect(DaemonClient.decodeHexPin('0' * 63), isNull);
      expect(DaemonClient.decodeHexPin('0' * 65), isNull);
      expect(DaemonClient.decodeHexPin('g' * 64), isNull);
      // Normative form is lowercase; uppercase must not slip through.
      expect(
          DaemonClient.decodeHexPin(_testCertFingerprint.toUpperCase()),
          isNull);
    });

    test('isHexPin agrees with decodeHexPin', () {
      expect(DaemonClient.isHexPin(_testCertFingerprint), isTrue);
      expect(DaemonClient.isHexPin('0' * 63), isFalse);
      expect(DaemonClient.isHexPin('x' * 64), isFalse);
    });
  });

  group('pinned client against a local HTTPS server', () {
    test('presented cert sha256 equals the expected 64-hex', () async {
      final server = await _startTlsServer();
      addTearDown(() => server.close(force: true));

      String? presented;
      final client = HttpClient()
        ..badCertificateCallback = (X509Certificate cert, String host,
            int port) {
          // The normative pin: SHA-256 of the DER-encoded leaf certificate.
          presented = sha256.convert(cert.der).toString();
          return true;
        };
      final request =
          await client.getUrl(Uri.parse('https://127.0.0.1:${server.port}/'));
      final response = await request.close();
      await response.drain<void>();
      client.close();

      expect(presented, _testCertFingerprint);
    });

    test('correct pin is accepted end-to-end', () async {
      final server = await _startTlsServer();
      addTearDown(() => server.close(force: true));

      final client = DaemonClient(
        baseUrl: 'https://127.0.0.1:${server.port}',
        pin: _testCertFingerprint,
      );
      addTearDown(client.close);

      // 204 -> null: reaching here proves the TLS handshake succeeded
      // against the pinned self-signed certificate.
      final session = await client.pollPending(waitSeconds: 1);
      expect(session, isNull);
    });

    test('wrong pin is rejected (handshake fails)', () async {
      final server = await _startTlsServer();
      addTearDown(() => server.close(force: true));

      // A valid 64-hex pin for a DIFFERENT certificate.
      final wrongPin = 'ab' * 32;
      expect(DaemonClient.isHexPin(wrongPin), isTrue);
      final client = DaemonClient(
        baseUrl: 'https://127.0.0.1:${server.port}',
        pin: wrongPin,
      );
      addTearDown(client.close);

      await expectLater(
        client.pollPending(waitSeconds: 1),
        throwsA(isA<HandshakeException>()),
      );
    });
  });

  group('https-only URL rules', () {
    test('default daemon URL is https', () {
      expect(KeyStore.defaultDaemonUrl, startsWith('https://'));
      expect(KeyStore.isHttpsUrl(KeyStore.defaultDaemonUrl), isTrue);
    });

    test('isHttpsUrl accepts only https', () {
      expect(KeyStore.isHttpsUrl('https://192.168.1.5:8766'), isTrue);
      expect(KeyStore.isHttpsUrl('http://192.168.1.5:8766'), isFalse);
      expect(KeyStore.isHttpsUrl('ftp://192.168.1.5:8766'), isFalse);
      expect(KeyStore.isHttpsUrl('not a url'), isFalse);
    });

    test('effectiveDaemonUrl drops stored non-https URLs', () {
      expect(KeyStore.effectiveDaemonUrl(null), KeyStore.defaultDaemonUrl);
      expect(KeyStore.effectiveDaemonUrl('http://192.168.1.5:8766'),
          KeyStore.defaultDaemonUrl);
      expect(KeyStore.effectiveDaemonUrl('https://192.168.1.5:8766'),
          'https://192.168.1.5:8766');
      expect(KeyStore.effectiveDaemonUrl('https://192.168.1.5:8766  '),
          'https://192.168.1.5:8766');
    });

    test('needsPairing forces re-entry without a valid https URL + pin', () {
      const pin = _testCertFingerprint;
      expect(KeyStore.needsPairing(null, pin), isTrue); // never configured
      expect(KeyStore.needsPairing('http://192.168.1.5:8766', pin),
          isTrue); // leftover cleartext
      expect(KeyStore.needsPairing('https://192.168.1.5:8766', null), isTrue);
      expect(KeyStore.needsPairing('https://192.168.1.5:8766', ''), isTrue);
      expect(
          KeyStore.needsPairing('https://192.168.1.5:8766', pin), isFalse);
    });
  });
}
