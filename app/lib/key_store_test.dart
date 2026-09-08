/// Tests for KeyStore pairing-state persistence: the paired Bluetooth
/// address is stored and read back, and clear() must wipe it together with
/// the Ed25519 private key so re-pairing starts from a fresh identity.
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
  group('KeyStore btAddress', () {
    test('stores and reads back the paired Bluetooth address', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.setBtAddress('D0:57:7E:C8:12:B5');

      expect(await store.btAddress(), 'D0:57:7E:C8:12:B5');
    });

    test('setBtAddress trims surrounding whitespace', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.setBtAddress('  D0:57:7E:C8:12:B5  ');

      expect(await store.btAddress(), 'D0:57:7E:C8:12:B5');
    });
  });

  group('KeyStore.clear', () {
    test('removes the Bluetooth address and Ed25519 private key', () async {
      final seed = base64.encode(List<int>.filled(32, 7));
      // Pinned under lib/ per the build plan; the test-only helper needs a
      // suppression for the same reason.
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({
        'bt_address': 'D0:57:7E:C8:12:B5',
        'ed25519_private_key': seed,
      });
      final store = KeyStore();

      expect(await store.load(), isNotNull);
      expect(await store.btAddress(), 'D0:57:7E:C8:12:B5');

      await store.clear();

      expect(await store.load(), isNull);
      expect(await store.btAddress(), isNull);
    });

    test('clear on an empty store is a no-op', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.clear();

      expect(await store.load(), isNull);
      expect(await store.btAddress(), isNull);
    });
  });
}
