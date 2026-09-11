/// Widget tests for the multi-computer approval screen, driven by a fake
/// [ConnectionManager] so no platform channel or real transport is involved.
/// Covers: gear menu split (forget vs reset identity), multi-computer card
/// grouping, deadline countdown disabling APPROVE/DENY, and "approved by
/// another phone" card reconciliation.
///
/// Canonical location per the build plan is lib/approval_screen_test.dart;
/// the test/approval_screen_test.dart delegator makes `flutter test`
/// discover these.
library;

import 'dart:async';
import 'dart:typed_data';

// ignore: depend_on_referenced_packages
import 'package:flutter/material.dart';
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';

import 'package:auth/approval_screen.dart';
import 'package:auth/connection_manager.dart';
import 'package:auth/daemon_client.dart';
import 'package:auth/key_store.dart';

Future<DeviceIdentity> _identity() async {
  final keyPair = await Ed25519().newKeyPair();
  return DeviceIdentity(keyPair: keyPair, publicKeyBase64: 'AQID');
}

PendingSession _pending({
  required String id,
  required String source,
  required String sourceName,
  DateTime? expiresAt,
}) =>
    PendingSession(
      id: id,
      nonce: Uint8List(32),
      user: 'alice',
      service: 'sudo',
      tty: '',
      expiresAt: expiresAt ?? DateTime.now().add(const Duration(seconds: 60)),
      source: source,
      sourceName: sourceName,
    );

class _FakeManager extends ConnectionManager {
  _FakeManager(DeviceIdentity identity)
      : super(keyStore: KeyStore(), identity: identity);

  final StreamController<PendingSession> pendingCtrl =
      StreamController<PendingSession>.broadcast();
  final StreamController<DecisionResult> decisionsCtrl =
      StreamController<DecisionResult>.broadcast();
  final StreamController<String> unregisteredCtrl =
      StreamController<String>.broadcast();
  final List<String> forgotten = <String>[];
  String myKey = 'mypc';

  @override
  Stream<PendingSession> pending() => pendingCtrl.stream;

  @override
  Stream<DecisionResult> decisions() => decisionsCtrl.stream;

  @override
  Stream<String> unregistered() => unregisteredCtrl.stream;

  @override
  String? welcomeKeyFor(String fingerprint) => myKey;

  @override
  Future<void> start() async {}

  @override
  Future<DecisionResult> postDecision({
    required PendingSession session,
    required String decision,
    required String signatureBase64,
  }) async =>
      DecisionResult(id: session.id, status: decision, key: myKey);

  @override
  Future<void> forgetComputer(String fingerprint) async {
    forgotten.add(fingerprint);
  }

  @override
  Future<void> dispose() async {
    await pendingCtrl.close();
    await decisionsCtrl.close();
    await unregisteredCtrl.close();
  }
}

Future<void> _settle(WidgetTester tester) async {
  await tester.pump();
  await tester.pump();
}

Future<void> _dispose(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump(const Duration(seconds: 4));
}

void main() {
  testWidgets('gear menu splits forget-this-computer from reset-identity',
      (tester) async {
    final identity = await _identity();
    var resetCalls = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          keyStore: KeyStore(),
          roster: const [
            RosterComputer(
                name: 'desk', fingerprint: 'fp1', lastAddr: '1.2.3.4:4443'),
          ],
          manager: _FakeManager(identity),
          onReset: () => resetCalls++,
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    await tester.tap(find.byIcon(Icons.settings));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400)); // sheet animates in

    expect(find.text('Forget desk'), findsOneWidget);
    expect(find.text('Reset identity'), findsOneWidget);

    await tester.tap(find.widgetWithText(ListTile, 'Reset identity'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400)); // sheet animates out
    expect(resetCalls, 1);

    await _dispose(tester);
  });

  testWidgets('renders one card per source computer', (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          keyStore: KeyStore(),
          roster: const [
            RosterComputer(
                name: 'desk', fingerprint: 'fp1', lastAddr: '1.2.3.4:4443'),
            RosterComputer(
                name: 'laptop', fingerprint: 'fp2', lastAddr: '1.2.3.5:4443'),
          ],
          manager: manager,
          authenticate: (_) async => false,
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    manager.pendingCtrl.add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    manager.pendingCtrl.add(
        _pending(id: 's2', source: 'fp2', sourceName: 'laptop'));
    await _settle(tester);

    expect(find.text('desk'), findsOneWidget);
    expect(find.text('laptop'), findsOneWidget);
    expect(find.byType(Card), findsNWidgets(2));

    await _dispose(tester);
  });

  testWidgets('countdown disables APPROVE/DENY at the deadline',
      (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          keyStore: KeyStore(),
          roster: const [
            RosterComputer(
                name: 'desk', fingerprint: 'fp1', lastAddr: '1.2.3.4:4443'),
          ],
          manager: manager,
          authenticate: (_) async => false,
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    manager.pendingCtrl.add(_pending(
      id: 's1',
      source: 'fp1',
      sourceName: 'desk',
      expiresAt: DateTime.now().add(const Duration(seconds: 2)),
    ));
    await _settle(tester);

    // Before the deadline the buttons are enabled.
    FilledButton approveButton() =>
        tester.widget<FilledButton>(find.widgetWithText(FilledButton, 'APPROVE'));
    expect(approveButton().onPressed, isNotNull);

    // Advance past the 2s deadline: the monotonic ticker hits zero and the
    // buttons disable.
    await tester.pump(const Duration(seconds: 3));
    expect(find.text('expired'), findsOneWidget);
    expect(approveButton().onPressed, isNull);
    expect(
      tester
          .widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'DENY'))
          .onPressed,
      isNull,
    );

    await _dispose(tester);
  });

  testWidgets('decision-result from another phone clears the card',
      (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          keyStore: KeyStore(),
          roster: const [
            RosterComputer(
                name: 'desk', fingerprint: 'fp1', lastAddr: '1.2.3.4:4443'),
          ],
          manager: manager,
          authenticate: (_) async => false,
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    manager.pendingCtrl.add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);
    expect(find.text('desk'), findsOneWidget);

    manager.decisionsCtrl.add(const DecisionResult(
        id: 's1', status: 'approved', key: 'otherpc', source: 'fp1'));
    await _settle(tester);

    expect(find.text('desk'), findsNothing);
    expect(find.text('No pending requests'), findsOneWidget);
    expect(find.text('已被 otherpc 批准'), findsOneWidget);

    await _dispose(tester);
  });

  testWidgets('unregistered computer clears its cards and prompts re-pair',
      (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          keyStore: KeyStore(),
          roster: const [
            RosterComputer(
                name: 'desk', fingerprint: 'fp1', lastAddr: '1.2.3.4:4443'),
          ],
          manager: manager,
          authenticate: (_) async => false,
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    manager.pendingCtrl.add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);
    expect(find.text('desk'), findsOneWidget);

    manager.unregisteredCtrl.add('fp1');
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400)); // dialog animates in

    expect(find.text('desk'), findsNothing);
    expect(find.text('密钥已失效'), findsOneWidget);
    expect(find.textContaining('不再认可此密钥'), findsOneWidget);

    await _dispose(tester);
  });
}
