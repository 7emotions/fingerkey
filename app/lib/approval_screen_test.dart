/// Widget tests for the multi-computer approval screen, driven by a fake
/// [ConnectionManager] so no platform channel or real transport is involved.
/// Covers: gear → settings page (sound toggle, forget vs reset identity),
/// multi-computer card grouping, deadline countdown disabling APPROVE/DENY,
/// deferred biometric prompt (fires on APPROVE tap, not on arrival), and
/// "approved by another phone" card reconciliation.
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
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'package:auth/approval_screen.dart';
import 'package:auth/connection_manager.dart';
import 'package:auth/daemon_client.dart';
import 'package:auth/key_store.dart';
import 'package:auth/service_bridge.dart';

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
  final List<String> postedDecisions = <String>[];
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
  }) async {
    postedDecisions.add(decision);
    return DecisionResult(id: session.id, status: decision, key: myKey);
  }

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

/// Records [ServiceLinkManager.setForeground] calls without touching the real
/// cross-engine bridge (no service isolate exists in widget tests).
class _FakeServiceLinkManager extends ServiceLinkManager {
  _FakeServiceLinkManager(DeviceIdentity identity)
      : super(keyStore: KeyStore(), identity: identity);

  final List<bool> foregroundCalls = <bool>[];

  @override
  Future<void> start() async {} // no bridge attach in tests

  @override
  Future<void> setForeground(bool foreground) async {
    foregroundCalls.add(foreground);
  }

  @override
  Future<void> dispose() async {} // skip the real bridge teardown
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
  testWidgets('gear opens settings page with sound toggle, forget, and reset',
      (tester) async {
    // ignore: invalid_use_of_visible_for_testing_member
    FlutterSecureStorage.setMockInitialValues({});
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
    await tester.pump(const Duration(milliseconds: 400)); // route animates in
    await _settle(tester); // loadSoundEnabled resolves

    expect(find.text('审批提示音'), findsOneWidget);
    expect(find.text('Forget desk'), findsOneWidget);
    expect(find.text('Reset identity'), findsOneWidget);

    await tester.tap(find.widgetWithText(ListTile, 'Reset identity'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400)); // route animates out
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

  testWidgets(
      'pending frame shows the card first; biometric fires only on APPROVE',
      (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    var authCalls = 0;
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
          authenticate: (_) async {
            authCalls++;
            return true;
          },
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    // A newly-arrived request renders the card immediately; no biometric
    // prompt is fired on arrival.
    manager.pendingCtrl
        .add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);

    expect(authCalls, 0);
    expect(find.text('desk'), findsOneWidget);
    expect(
      find.text(
          'Request pending — review reason/command, then approve or deny.'),
      findsOneWidget,
    );

    // Tapping APPROVE is what fires the biometric prompt; on success the
    // signed decision is posted and the card clears.
    await tester.tap(find.widgetWithText(FilledButton, 'APPROVE'));
    await _settle(tester);

    expect(authCalls, 1);
    expect(find.text('desk'), findsNothing);
    expect(find.text('No pending requests'), findsOneWidget);

    await _dispose(tester);
  });

  testWidgets(
      'overlay APPROVE before the card prompts biometric exactly once',
      (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    final launch = StreamController<Map<String, dynamic>>.broadcast();
    var authCalls = 0;
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
          authenticate: (_) async {
            authCalls++;
            return true;
          },
          overlayApproveStream: launch.stream,
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    // Real cold-start order (task 12): the overlay launch event lands while
    // the bridge is still attaching, before the snapshot replay delivers the
    // card. No prompt may fire until the card exists.
    launch.add(<String, dynamic>{
      'id': 's1',
      'source': 'fp1',
      'expiresAt': DateTime.now()
          .add(const Duration(seconds: 60))
          .millisecondsSinceEpoch,
    });
    await _settle(tester);
    expect(authCalls, 0);
    expect(manager.postedDecisions, isEmpty);

    // The snapshot replay delivers the card: the biometric prompt fires once
    // and the signed approve decision is posted.
    manager.pendingCtrl
        .add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);

    expect(authCalls, 1);
    expect(manager.postedDecisions, <String>['approve']);
    expect(find.text('desk'), findsNothing);

    // A replayed payload for the already-approved session is idempotent.
    launch.add(<String, dynamic>{
      'id': 's1',
      'source': 'fp1',
      'expiresAt': DateTime.now()
          .add(const Duration(seconds: 60))
          .millisecondsSinceEpoch,
    });
    await _settle(tester);
    expect(authCalls, 1);
    expect(manager.postedDecisions, <String>['approve']);

    await launch.close();
    await _dispose(tester);
  });

  testWidgets('overlay APPROVE after the card prompts biometric exactly once',
      (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    final launch = StreamController<Map<String, dynamic>>.broadcast();
    var authCalls = 0;
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
          authenticate: (_) async {
            authCalls++;
            return true;
          },
          overlayApproveStream: launch.stream,
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    // Card first (snapshot replay won the race), then the launch event:
    // the prompt still fires exactly once.
    manager.pendingCtrl
        .add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);
    expect(authCalls, 0);

    launch.add(<String, dynamic>{
      'id': 's1',
      'source': 'fp1',
      'expiresAt': DateTime.now()
          .add(const Duration(seconds: 60))
          .millisecondsSinceEpoch,
    });
    await _settle(tester);

    expect(authCalls, 1);
    expect(manager.postedDecisions, <String>['approve']);
    expect(find.text('desk'), findsNothing);

    await launch.close();
    await _dispose(tester);
  });

  testWidgets(
      'overlay APPROVE for an unknown session prompts nothing and expires',
      (tester) async {
    final identity = await _identity();
    final manager = _FakeManager(identity);
    final launch = StreamController<Map<String, dynamic>>.broadcast();
    var authCalls = 0;
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
          authenticate: (_) async {
            authCalls++;
            return true;
          },
          overlayApproveStream: launch.stream,
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);

    // The session was already decided/expired elsewhere: its card never
    // arrives, so no prompt fires and the marker is pruned at expiry.
    launch.add(<String, dynamic>{
      'id': 'gone',
      'source': 'fp1',
      'expiresAt': DateTime.now()
          .add(const Duration(seconds: 1))
          .millisecondsSinceEpoch,
    });
    await _settle(tester);
    expect(authCalls, 0);

    await tester.pump(const Duration(seconds: 2));
    await _settle(tester);
    expect(authCalls, 0);
    expect(manager.postedDecisions, isEmpty);

    await launch.close();
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

  testWidgets('swipe-to-dismiss removes the card locally, sends no decision',
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

    await tester.drag(find.byType(Dismissible), const Offset(-500, 0));
    await tester.pumpAndSettle();

    expect(find.text('desk'), findsNothing);
    expect(find.text('No pending requests'), findsOneWidget);
    expect(manager.postedDecisions, isEmpty);

    await _dispose(tester);
  });

  testWidgets('clear-all X empties the list and is a no-op when empty',
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

    // No-op on an empty list: no crash, no decision, empty state stays.
    await tester.tap(find.byIcon(Icons.close));
    await _settle(tester);
    expect(find.text('No pending requests'), findsOneWidget);
    expect(manager.postedDecisions, isEmpty);

    manager.pendingCtrl.add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    manager.pendingCtrl.add(
        _pending(id: 's2', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);
    expect(find.byType(Card), findsNWidgets(2));

    await tester.tap(find.byIcon(Icons.close));
    await _settle(tester);

    expect(find.text('No pending requests'), findsOneWidget);
    expect(find.byType(Card), findsNothing);
    expect(manager.postedDecisions, isEmpty);

    await _dispose(tester);
  });

  testWidgets('approval sound plays once per request when enabled',
      (tester) async {
    // ignore: invalid_use_of_visible_for_testing_member
    FlutterSecureStorage.setMockInitialValues({});
    final identity = await _identity();
    final manager = _FakeManager(identity);
    var soundCalls = 0;
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
          playSound: () async {
            soundCalls++;
          },
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester); // loadSoundEnabled resolves (defaults on)

    manager.pendingCtrl
        .add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);
    expect(soundCalls, 1);

    // A duplicate frame for the same session does not replay the sound.
    manager.pendingCtrl
        .add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);
    expect(soundCalls, 1);

    await _dispose(tester);
  });

  testWidgets('approval sound is muted when the toggle is off',
      (tester) async {
    // ignore: invalid_use_of_visible_for_testing_member
    FlutterSecureStorage.setMockInitialValues({'sound_enabled': '0'});
    final identity = await _identity();
    final manager = _FakeManager(identity);
    var soundCalls = 0;
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
          playSound: () async {
            soundCalls++;
          },
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester); // loadSoundEnabled resolves to false

    manager.pendingCtrl
        .add(_pending(id: 's1', source: 'fp1', sourceName: 'desk'));
    await _settle(tester);

    expect(find.text('desk'), findsOneWidget);
    expect(soundCalls, 0);

    await _dispose(tester);
    // ignore: invalid_use_of_visible_for_testing_member
    FlutterSecureStorage.setMockInitialValues({});
  });

  testWidgets(
      'backgrounding detaches the bridge (foreground=false), transient '
      'inactive and resume keep it attached (task 15/16)', (tester) async {
    final identity = await _identity();
    final manager = _FakeServiceLinkManager(identity);
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
          onReset: () {},
          onRosterChanged: () {},
        ),
      ),
    );
    await _settle(tester);
    // No lifecycle transition while the screen just opened: foreground claim
    // is untouched (the in-app card + SystemSound path still owns alerts).
    expect(manager.foregroundCalls, isEmpty);

    // Backgrounded: the observer must detach so the service engine's
    // `_sendToUi` sees no registered UI port and fires the overlay path.
    // ignore: invalid_use_of_protected_member
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await _settle(tester);
    expect(manager.foregroundCalls, <bool>[false]);

    // Transient inactive — Android pauses the Activity for system dialogs
    // such as BiometricPrompt without stopping it — must NOT detach: the
    // bridge stays up so the post-decision RPC issued after the prompt
    // succeeds instead of throwing "ui bridge not attached".
    // ignore: invalid_use_of_protected_member
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await _settle(tester);
    expect(manager.foregroundCalls, <bool>[false, true]);

    // Resumed: re-attach re-registers the port and replays the snapshot.
    // ignore: invalid_use_of_protected_member
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await _settle(tester);
    expect(manager.foregroundCalls, <bool>[false, true, true]);

    await _dispose(tester);
  });
}
