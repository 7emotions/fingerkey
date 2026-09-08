/// Tests for KeyStore pairing-state persistence: clear() must wipe the
/// daemon URL, certificate pin and Ed25519 private key so re-pairing starts
/// from a fresh identity.
///
/// Canonical location per the build plan is lib/key_store_test.dart; the
/// test/key_store_test.dart delegator makes `flutter test` discover these.
library;

import 'dart:convert';

// Test-only file pinned at lib/ per the build plan; the runner entry point
// is test/key_store_test.dart.
// ignore: depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'package:auth/key_store.dart';

void main() {
  group('KeyStore.clear', () {
    test('removes daemon URL, cert pin and Ed25519 private key', () async {
      final seed = base64.encode(List<int>.filled(32, 7));
      // Pinned under lib/ per the build plan; the test-only helper needs a
      // suppression for the same reason.
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({
        'daemon_url': 'https://192.168.1.5:8766',
        'daemon_cert_pin': 'ab' * 32,
        'ed25519_private_key': seed,
      });
      final store = KeyStore();

      expect(await store.load(), isNotNull);
      expect(await store.daemonUrlStored(), 'https://192.168.1.5:8766');
      expect(await store.certPin(), 'ab' * 32);

      await store.clear();

      expect(await store.load(), isNull);
      expect(await store.daemonUrlStored(), isNull);
      expect(await store.certPin(), isNull);
    });

    test('clear on an empty store is a no-op', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.clear();

      expect(await store.load(), isNull);
      expect(await store.daemonUrlStored(), isNull);
      expect(await store.certPin(), isNull);
    });
  });
}
