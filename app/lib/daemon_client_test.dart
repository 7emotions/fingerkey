/// Tests for the v2 daemon client: hello/welcome handshake, pending dedup,
/// idempotent postDecision and the decisions() broadcast. Driven by a fake
/// [TcpTlsLink] so no platform channel is involved.
///
/// Canonical location per the build plan is lib/daemon_client_test.dart; the
/// test/daemon_client_test.dart delegator makes `flutter test` discover these.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';

import 'package:auth/daemon_client.dart';
import 'package:auth/frame.dart';
import 'package:auth/tcp_tls_link.dart';

/// A fake link: captures connects/sends and lets the test inject daemon
/// frames as `data` events.
class _FakeLink extends TcpTlsLink {
  final StreamController<TcpEvent> controller =
      StreamController<TcpEvent>.broadcast();
  final List<String> sentFrames = <String>[];
  String? host;
  int? port;
  String? fp;

  @override
  Stream<TcpEvent> get events => controller.stream;

  @override
  Future<int> connect(String host, int port, String fp) async {
    this.host = host;
    this.port = port;
    this.fp = fp;
    return 42;
  }

  @override
  Future<void> send(Uint8List payload) async {
    // The client frames every send (4-byte length prefix); strip it and
    // record the JSON payload.
    sentFrames.add(utf8.decode(payload.sublist(4)));
  }

  @override
  Future<void> disconnect() async {}

  void emitData(String json) => controller.add(
        TcpEvent(
          id: 42,
          status: 'data',
          data: encodeFrame(Uint8List.fromList(utf8.encode(json))),
        ),
      );

  Future<void> close() => controller.close();
}

String _pendingJson(String id) => json.encode(<String, dynamic>{
      'type': 'pending',
      'id': id,
      'nonce': base64.encode(List<int>.filled(32, 1)),
      'user': 'alice',
      'service': 'sudo',
      'tty': '',
      'expires_at': 2000000000,
    });

Future<void> _flush() => Future<void>.delayed(Duration.zero);

void main() {
  test('connect sends hello{pubkey,name} and parses welcome with pending',
      () async {
    final link = _FakeLink();
    final client = DaemonClient(link: link, pubkey: 'PUBKEY', phoneName: 'pixel');

    final welcomeFuture =
        client.connect(host: '192.168.1.5', port: 4443, fp: 'abc');
    await _flush();

    expect(link.host, '192.168.1.5');
    expect(link.port, 4443);
    expect(link.fp, 'abc');
    expect(link.sentFrames, hasLength(1));
    final hello = json.decode(link.sentFrames.first) as Map<String, dynamic>;
    expect(hello['type'], 'hello');
    expect(hello['pubkey'], 'PUBKEY');
    expect(hello['name'], 'pixel');
    expect(hello.containsKey('token'), isFalse);

    link.emitData(json.encode(<String, dynamic>{
      'type': 'welcome',
      'registered': true,
      'key': 'mypc',
      'pending': <dynamic>[json.decode(_pendingJson('s1'))],
    }));

    final welcome = await welcomeFuture;
    expect(welcome.registered, isTrue);
    expect(welcome.key, 'mypc');
    expect(welcome.pending, hasLength(1));
    expect(welcome.pending.first.id, 's1');
    expect(welcome.pending.first.expiresAt,
        DateTime.fromMillisecondsSinceEpoch(2000000000 * 1000));
    expect(client.welcomeKey, 'mypc');

    await client.dispose();
    await link.close();
  });

  test('connect with a token sends hello{token} and parses registered',
      () async {
    final link = _FakeLink();
    final client = DaemonClient(link: link, pubkey: 'PUBKEY');

    final welcomeFuture = client.connect(
      host: '10.0.0.7',
      port: 4443,
      fp: 'beef',
      token: 't0ken',
    );
    await _flush();

    final hello = json.decode(link.sentFrames.first) as Map<String, dynamic>;
    expect(hello['token'], 't0ken');

    link.emitData(json.encode(<String, dynamic>{
      'type': 'registered',
      'key': 'desk',
    }));

    final welcome = await welcomeFuture;
    expect(welcome.registered, isTrue);
    expect(welcome.key, 'desk');
    expect(welcome.pending, isEmpty);

    await client.dispose();
    await link.close();
  });

  test('pending stream dedups welcome snapshot vs live push by id', () async {
    final link = _FakeLink();
    final client = DaemonClient(link: link, pubkey: 'PUBKEY');
    final received = <String>[];
    final sub = client.pending().listen((s) => received.add(s.id));

    final welcomeFuture =
        client.connect(host: 'h', port: 1, fp: 'f');
    await _flush();

    link.emitData(json.encode(<String, dynamic>{
      'type': 'welcome',
      'registered': true,
      'key': 'mypc',
      'pending': <dynamic>[json.decode(_pendingJson('s1'))],
    }));
    await welcomeFuture;

    // The same id pushed again (snapshot ∩ subscription overlap) must be
    // dropped.
    link.emitData(_pendingJson('s1'));
    await _flush();

    expect(received, <String>['s1']);

    await sub.cancel();
    await client.dispose();
    await link.close();
  });

  test('postDecision sends a decision frame and resolves the result', () async {
    final link = _FakeLink();
    final client = DaemonClient(link: link, pubkey: 'PUBKEY');

    final welcomeFuture =
        client.connect(host: 'h', port: 1, fp: 'f');
    await _flush();
    link.emitData(json.encode(<String, dynamic>{
      'type': 'welcome',
      'registered': true,
      'key': 'mypc',
      'pending': <dynamic>[],
    }));
    await welcomeFuture;
    final sentBefore = link.sentFrames.length;

    final resultFuture = client.postDecision(
      sessionId: 's9',
      decision: 'approve',
      signatureBase64: 'SIG',
    );
    await _flush();
    expect(link.sentFrames.length, sentBefore + 1);
    final decision =
        json.decode(link.sentFrames.last) as Map<String, dynamic>;
    expect(decision['type'], 'decision');
    expect(decision['id'], 's9');
    expect(decision['decision'], 'approve');
    expect(decision['sig'], 'SIG');

    link.emitData(json.encode(<String, dynamic>{
      'type': 'decision-result',
      'id': 's9',
      'status': 'approved',
      'key': 'mypc',
    }));

    final result = await resultFuture;
    expect(result.status, 'approved');
    expect(result.key, 'mypc');
    expect(result.isError, isFalse);

    await client.dispose();
    await link.close();
  });

  test('decisions() stream yields every decision-result, source-tagged',
      () async {
    final link = _FakeLink();
    final client =
        DaemonClient(link: link, pubkey: 'PUBKEY', source: 'fp1');
    final results = <DecisionResult>[];
    final sub = client.decisions().listen(results.add);

    link.emitData(json.encode(<String, dynamic>{
      'type': 'decision-result',
      'id': 's1',
      'status': 'denied',
      'key': 'otherpc',
    }));
    await _flush();

    expect(results, hasLength(1));
    expect(results.first.id, 's1');
    expect(results.first.status, 'denied');
    expect(results.first.key, 'otherpc');
    expect(results.first.source, 'fp1');

    await sub.cancel();
    await client.dispose();
    await link.close();
  });

  test('an oversized frame is dropped and the next valid frame still parses',
      () async {
    final link = _FakeLink();
    final client = DaemonClient(link: link, pubkey: 'PUBKEY');
    final received = <String>[];
    final sub = client.pending().listen((s) => received.add(s.id));

    final welcomeFuture = client.connect(host: 'h', port: 1, fp: 'f');
    await _flush();
    link.emitData(json.encode(<String, dynamic>{
      'type': 'welcome',
      'registered': true,
      'key': 'mypc',
      'pending': <dynamic>[],
    }));
    await welcomeFuture;

    // A frame declaring a huge length (oversized header) must be dropped and
    // the decoder reset, so the following valid pending still arrives.
    final oversizeHeader = Uint8List(4);
    ByteData.sublistView(oversizeHeader).setUint32(0, 0x7FFFFFFF, Endian.big);
    link.controller.add(TcpEvent(id: 42, status: 'data', data: oversizeHeader));
    link.emitData(_pendingJson('s2'));
    await _flush();

    expect(received, <String>['s2']);

    await sub.cancel();
    await client.dispose();
    await link.close();
  });

  test('PendingSession.fromFrameJson parses reason/command when present',
      () async {
    final session = PendingSession.fromFrameJson(json.decode(json.encode(
      <String, dynamic>{
        'type': 'pending',
        'id': 's1',
        'nonce': base64.encode(List<int>.filled(32, 1)),
        'user': 'alice',
        'service': 'sudo',
        'tty': '',
        'reason': 'system update',
        'command': 'apt upgrade',
        'expires_at': 2000000000,
      },
    )) as Map<String, dynamic>);

    expect(session.id, 's1');
    expect(session.reason, 'system update');
    expect(session.command, 'apt upgrade');
  });

  test('PendingSession.fromFrameJson defaults reason/command to empty',
      () async {
    final session = PendingSession.fromFrameJson(
        json.decode(_pendingJson('s1')) as Map<String, dynamic>);

    expect(session.id, 's1');
    expect(session.reason, '');
    expect(session.command, '');
  });

  test('in-flight decision is re-posted idempotently on reconnect', () async {
    final link = _FakeLink();
    final client = DaemonClient(link: link, pubkey: 'PUBKEY');

    Future<void> connectAndWelcome() async {
      final future = client.connect(host: 'h', port: 1, fp: 'f');
      await _flush();
      link.emitData(json.encode(<String, dynamic>{
        'type': 'welcome',
        'registered': true,
        'key': 'mypc',
        'pending': <dynamic>[],
      }));
      await future;
    }

    await connectAndWelcome();

    // Post a decision that will not be answered yet — it stays in-flight.
    final resultFuture = client.postDecision(
      sessionId: 's9',
      decision: 'approve',
      signatureBase64: 'SIG',
    );
    await _flush();
    int decisionCount() => link.sentFrames
        .where((f) =>
            (json.decode(f) as Map<String, dynamic>)['type'] == 'decision')
        .length;
    expect(decisionCount(), 1);

    // Reconnect: the client re-posts the in-flight decision.
    await connectAndWelcome();
    await _flush();
    expect(decisionCount(), 2);

    // The verdict arrives after the reconnect.
    link.emitData(json.encode(<String, dynamic>{
      'type': 'decision-result',
      'id': 's9',
      'status': 'approved',
      'key': 'mypc',
    }));
    final result = await resultFuture;
    expect(result.status, 'approved');

    await client.dispose();
    await link.close();
  });
}
