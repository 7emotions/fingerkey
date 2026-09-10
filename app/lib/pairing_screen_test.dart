/// Tests for QR pairing: `phonefprint://` parsing and the scan → connect →
/// `registered` → addComputer flow, plus a widget test driving the screen
/// through an injected scanner.
///
/// Canonical location per the build plan is lib/pairing_screen_test.dart; the
/// test/pairing_screen_test.dart delegator makes `flutter test` discover these.
library;

import 'dart:async';

// ignore: depend_on_referenced_packages
import 'package:flutter/material.dart';
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'package:auth/daemon_client.dart';
import 'package:auth/key_store.dart';
import 'package:auth/pairing_screen.dart';
import 'package:auth/tcp_tls_link.dart';

class _NoopLink extends TcpTlsLink {
  @override
  Stream<TcpEvent> get events => Stream<TcpEvent>.empty();
}

class _FakeClient extends DaemonClient {
  _FakeClient() : super(pubkey: 'PUBKEY', link: _NoopLink());

  String? host;
  int? port;
  String? fp;
  String? token;

  @override
  Future<Welcome> connect({
    required String host,
    required int port,
    required String fp,
    String? token,
  }) async {
    this.host = host;
    this.port = port;
    this.fp = fp;
    this.token = token;
    return const Welcome(registered: true, key: 'desk', pending: []);
  }

  @override
  Future<void> dispose() async {}
}

Future<DeviceIdentity> _identity() async {
  final keyPair = await Ed25519().newKeyPair();
  return DeviceIdentity(keyPair: keyPair, publicKeyBase64: 'AQID');
}

void main() {
  group('PairRequest.parse', () {
    test('parses a full phonefprint:// URI', () {
      final req = PairRequest.parse(
          'phonefprint://192.0.2.1:4443?fp=deadbeef&t=t0ken&n=desk');
      expect(req.ip, '192.0.2.1');
      expect(req.port, 4443);
      expect(req.fp, 'deadbeef');
      expect(req.token, 't0ken');
      expect(req.name, 'desk');
    });

    test('defaults the port to 4443 when absent', () {
      final req = PairRequest.parse('phonefprint://192.0.2.1?fp=beef&t=t&n=x');
      expect(req.port, 4443);
    });

    test('rejects a non-phonefprint URI', () {
      expect(() => PairRequest.parse('https://example.com?fp=x'),
          throwsFormatException);
    });
  });

  test('pairFromQr connects with token, adds the computer to the roster',
      () async {
    // ignore: invalid_use_of_visible_for_testing_member
    FlutterSecureStorage.setMockInitialValues({});
    final keyStore = KeyStore();
    final identity = await _identity();
    final client = _FakeClient();

    final added = await pairFromQr(
      qr: 'phonefprint://192.0.2.1:4443?fp=deadbeef&t=t0ken&n=desk',
      identity: identity,
      keyStore: keyStore,
      clientFactory: () => client,
      browse: () async => const [],
    );

    expect(client.host, '192.0.2.1');
    expect(client.port, 4443);
    expect(client.fp, 'deadbeef');
    expect(client.token, 't0ken');
    expect(added.name, 'desk');
    expect(added.lastAddr, '192.0.2.1:4443');

    final roster = await keyStore.roster();
    expect(roster, hasLength(1));
    expect(roster.first.name, 'desk');
    expect(roster.first.fingerprint, 'deadbeef');
  });

  testWidgets('scanning a QR pairs and invokes onPaired', (tester) async {
    // ignore: invalid_use_of_visible_for_testing_member
    FlutterSecureStorage.setMockInitialValues({});
    final keyStore = KeyStore();
    final identity = await _identity();
    final client = _FakeClient();
    var paired = 0;

    await tester.pumpWidget(
      MaterialApp(
        home: PairingScreen(
          keyStore: keyStore,
          identity: identity,
          onPaired: (_) => paired++,
          clientFactory: () => client,
          browse: () async => const [],
          scannerBuilder: (context, onScanned) => TextButton(
            onPressed: () =>
                onScanned('phonefprint://192.0.2.1:4443?fp=abc&t=t&n=desk'),
            child: const Text('scan'),
          ),
        ),
      ),
    );
    await tester.pump();

    await tester.tap(find.text('scan'));
    await tester.pump();
    await tester.pump();

    expect(paired, 1);
    expect((await keyStore.roster()).single.name, 'desk');

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump();
  });
}
