/// Widget test for the approval screen's re-pair affordance: tapping the
/// settings button in the AppBar must invoke the [ApprovalScreen.onReset]
/// callback supplied by main.dart (which clears the KeyStore and falls back
/// to the pairing screen).
///
/// Canonical location per the build plan is lib/approval_screen_test.dart;
/// the test/approval_screen_test.dart delegator makes `flutter test`
/// discover these.
library;

// Test-only file pinned at lib/ per the build plan; the runner entry point
// is test/approval_screen_test.dart.
// ignore: depend_on_referenced_packages
import 'package:flutter/material.dart';
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';

import 'package:auth/approval_screen.dart';
import 'package:auth/key_store.dart';

/// 64 lowercase hex chars (valid pin).
const String _hex64 =
    '3c39e582a040d31dcdb5b3da2e0bc965fb9b050efc02495ec3b1d6570a2b03a3';

Future<DeviceIdentity> _identity() async {
  final keyPair = await Ed25519().newKeyPair();
  return DeviceIdentity(keyPair: keyPair, publicKeyBase64: 'AQID');
}

void main() {
  testWidgets('settings tap invokes the onReset callback', (tester) async {
    final identity = await _identity();
    var resetCalls = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: ApprovalScreen(
          identity: identity,
          daemonUrl: 'https://192.168.1.5:8766',
          certPin: _hex64,
          onReset: () => resetCalls++,
        ),
      ),
    );
    await tester.pump(); // let the first long-poll attempt fail

    expect(find.byIcon(Icons.settings), findsOneWidget);
    expect(resetCalls, 0);
    await tester.tap(find.byIcon(Icons.settings));
    await tester.pump();

    expect(resetCalls, 1);

    // Dispose the screen (stops the poll loop) and flush the 3 s retry
    // timer so no timers are left pending at the end of the test.
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 4));
  });
}
