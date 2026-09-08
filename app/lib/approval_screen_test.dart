/// Widget tests for the approval screen: the re-pair affordance (settings
/// tap must invoke [ApprovalScreen.onReset]) and the connection banner,
/// driven by an injected fake [BtClient] so no platform channel is involved.
///
/// Canonical location per the build plan is lib/approval_screen_test.dart;
/// the test/approval_screen_test.dart delegator makes `flutter test`
/// discover these.
library;

import 'dart:async';

// Test-only file pinned at lib/ per the build plan; the runner entry point
// is test/approval_screen_test.dart.
// ignore: depend_on_referenced_packages
import 'package:flutter/material.dart';
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';

import 'package:auth/approval_screen.dart';
import 'package:auth/bt_link.dart';
import 'package:auth/daemon_client.dart';
import 'package:auth/key_store.dart';

const String _btAddress = 'D0:57:7E:C8:12:B5';

Future<DeviceIdentity> _identity() async {
  final keyPair = await Ed25519().newKeyPair();
  return DeviceIdentity(keyPair: keyPair, publicKeyBase64: 'AQID');
}

/// Fake transport: [connect] succeeds and posts a matching `connected`
/// event; [connection] is a broadcast controller the tests drive.
class _FakeBtClient extends BtClient {
  _FakeBtClient() : super(link: BtLink());

  final StreamController<ConnectionStatus> _connections =
      StreamController<ConnectionStatus>.broadcast();
  int connectCalls = 0;

  @override
  Stream<PendingSession> pending() => const Stream<PendingSession>.empty();

  @override
  Stream<ConnectionStatus> connection() => _connections.stream;

  @override
  Future<void> connect(String address) async {
    connectCalls++;
    _connections.add(ConnectionStatus(connected: true, address: address));
  }

  void emitDisconnected() {
    _connections
        .add(ConnectionStatus(connected: false, address: _btAddress));
  }
}

Future<void> _settle(WidgetTester tester) async {
  await tester.pump(); // flush connect microtasks + event delivery
  await tester.pump();
}

void main() {
  testWidgets('settings tap invokes the onReset callback', (tester) async {
    final identity = await _identity();
    var resetCalls = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          btAddress: _btAddress,
          client: _FakeBtClient(),
          onReset: () => resetCalls++,
        ),
      ),
    );
    await _settle(tester);

    expect(find.byIcon(Icons.settings), findsOneWidget);
    expect(resetCalls, 0);
    await tester.tap(find.byIcon(Icons.settings));
    await tester.pump();

    expect(resetCalls, 1);

    // Dispose the screen (cancels the BT subscriptions and any pending
    // reconnect timer) so nothing is left running at the end of the test.
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 4));
  });

  testWidgets('shows the connected banner once the link is up',
      (tester) async {
    final identity = await _identity();
    final client = _FakeBtClient();
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          btAddress: _btAddress,
          client: client,
          onReset: () {},
        ),
      ),
    );
    await _settle(tester);

    expect(client.connectCalls, 1);
    expect(find.text('connected to $_btAddress'), findsOneWidget);
    expect(find.textContaining('disconnected'), findsNothing);

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 4));
  });

  testWidgets('drop → disconnected banner → auto-reconnect after 3s',
      (tester) async {
    final identity = await _identity();
    final client = _FakeBtClient();
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          btAddress: _btAddress,
          client: client,
          onReset: () {},
        ),
      ),
    );
    await _settle(tester);
    expect(find.text('connected to $_btAddress'), findsOneWidget);

    // The daemon drops the socket: the banner must flip to disconnected
    // and a reconnect must be armed.
    client.emitDisconnected();
    await _settle(tester);
    expect(find.text('disconnected — reconnecting…'), findsOneWidget);
    expect(client.connectCalls, 1); // no reconnect yet

    // 3s backoff elapses → reconnect → connected again.
    await tester.pump(const Duration(seconds: 3));
    await _settle(tester);
    expect(client.connectCalls, 2);
    expect(find.text('connected to $_btAddress'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 4));
  });
}
