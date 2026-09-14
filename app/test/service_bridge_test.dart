/// Tests for the cross-engine service bridge (task 21): the reset RPC wiring
/// (a stale link manager is dropped so the freshly generated identity can
/// connect) and the native alert dismissal on terminal results (overlay
/// `hideForId` + notification `cancel`).
library;

import 'dart:isolate';
import 'dart:ui' as ui;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:auth/service_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('UiBridge.reset sends a reset RPC to the service isolate', () async {
    // A fake service port: answers every request with null and records the
    // requested methods, so attach() (welcomeKeys + snapshot + start)
    // succeeds and the reset RPC is observable.
    final requests = <String>[];
    final servicePort = ReceivePort();
    ui.IsolateNameServer.registerPortWithName(
        servicePort.sendPort, kServicePortName);
    servicePort.listen((raw) {
      if (raw is! Map || raw['type'] != 'request') return;
      final method = raw['method'];
      if (method is String) requests.add(method);
      final replyTo = raw['replyTo'];
      if (replyTo is SendPort) {
        replyTo.send(<String, dynamic>{
          'type': 'reply',
          'id': raw['id'],
          'value': null,
        });
      }
    });
    final bridge = UiBridge();
    try {
      await bridge.attach();
      await bridge.reset();
      expect(requests, contains('reset'));
    } finally {
      await bridge.dispose();
      ui.IsolateNameServer.removePortNameMapping(kServicePortName);
      servicePort.close();
    }
  });

  test('dismissAlertsFor hides the overlay card and cancels the notification',
      () async {
    final overlayCalls = <MethodCall>[];
    final notifyCalls = <MethodCall>[];
    const overlayChannel = MethodChannel('com.phonefprint.auth/overlay');
    const notifyChannel = MethodChannel('com.phonefprint.auth/notify');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      ..setMockMethodCallHandler(overlayChannel, (call) async {
        overlayCalls.add(call);
        return null;
      })
      ..setMockMethodCallHandler(notifyChannel, (call) async {
        notifyCalls.add(call);
        return null;
      });
    final service = BackgroundLinkService();
    try {
      await service.dismissAlertsFor('s1');

      expect(overlayCalls, hasLength(1));
      expect(overlayCalls.single.method, 'hideForId');
      expect((overlayCalls.single.arguments as Map)['id'], 's1');

      expect(notifyCalls, hasLength(1));
      expect(notifyCalls.single.method, 'cancel');
      expect((notifyCalls.single.arguments as Map)['id'], 's1');
    } finally {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        ..setMockMethodCallHandler(overlayChannel, null)
        ..setMockMethodCallHandler(notifyChannel, null);
    }
  });

  test('dismissAlertsFor swallows missing native channels', () async {
    // No mock handlers: both channels throw MissingPluginException, which the
    // dismissal path must swallow (fire-and-forget in production).
    final service = BackgroundLinkService();
    await service.dismissAlertsFor('s1'); // must not throw
  });
}
