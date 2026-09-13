/// Tests for KeyStore roster persistence: the roster of paired computers
/// (`[{name, fingerprint, lastAddr}]`) replaces the old single bt_address.
/// `removeComputer` keeps the Ed25519 key; `resetIdentity` wipes both.
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
  group('KeyStore roster', () {
    test('addComputer stores and reads back name/fingerprint/lastAddr',
        () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.addComputer(
        name: 'desk',
        fingerprint: 'abc123',
        lastAddr: '192.168.1.5:4443',
      );

      final roster = await store.roster();
      expect(roster, hasLength(1));
      expect(roster.first.name, 'desk');
      expect(roster.first.fingerprint, 'abc123');
      expect(roster.first.lastAddr, '192.168.1.5:4443');
    });

    test('addComputer upserts by fingerprint (keeps name, moves lastAddr)',
        () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.addComputer(
        name: 'desk',
        fingerprint: 'abc123',
        lastAddr: '192.168.1.5:4443',
      );
      await store.addComputer(
        name: '',
        fingerprint: 'abc123',
        lastAddr: '192.168.1.9:4443',
      );

      final roster = await store.roster();
      expect(roster, hasLength(1));
      expect(roster.first.fingerprint, 'abc123');
      expect(roster.first.name, 'desk'); // empty name keeps the old one
      expect(roster.first.lastAddr, '192.168.1.9:4443');
    });

    test('roster on an empty store is empty', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      expect(await KeyStore().roster(), isEmpty);
    });
  });

  group('removeComputer / resetIdentity', () {
    test('removeComputer removes the computer but keeps the key', () async {
      final seed = base64.encode(List<int>.filled(32, 7));
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({
        'ed25519_private_key': seed,
      });
      final store = KeyStore();
      await store.addComputer(
        name: 'desk',
        fingerprint: 'abc123',
        lastAddr: '192.168.1.5:4443',
      );

      await store.removeComputer('abc123');

      expect(await store.roster(), isEmpty);
      expect(await store.load(), isNotNull); // key retained
    });

    test('resetIdentity clears the roster and the Ed25519 key', () async {
      final seed = base64.encode(List<int>.filled(32, 7));
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({
        'ed25519_private_key': seed,
      });
      final store = KeyStore();
      await store.addComputer(
        name: 'desk',
        fingerprint: 'abc123',
        lastAddr: '192.168.1.5:4443',
      );

      await store.resetIdentity();

      expect(await store.roster(), isEmpty);
      expect(await store.load(), isNull);
    });

    test('resetIdentity on an empty store is a no-op', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.resetIdentity();

      expect(await store.roster(), isEmpty);
      expect(await store.load(), isNull);
    });
  });

  group('soundEnabled pref', () {
    test('missing key defaults to true', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      expect(await KeyStore().loadSoundEnabled(), isTrue);
    });

    test('setSoundEnabled(false) persists and reads back false', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({});
      final store = KeyStore();

      await store.setSoundEnabled(false);
      expect(await store.loadSoundEnabled(), isFalse);

      await store.setSoundEnabled(true);
      expect(await store.loadSoundEnabled(), isTrue);
    });

    test('corrupt value falls back to true', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({'sound_enabled': 'garbage'});
      expect(await KeyStore().loadSoundEnabled(), isTrue);
    });

    test('explicit "0" reads back false', () async {
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({'sound_enabled': '0'});
      expect(await KeyStore().loadSoundEnabled(), isFalse);
    });

    test('resetIdentity keeps the sound pref', () async {
      final seed = base64.encode(List<int>.filled(32, 7));
      // ignore: invalid_use_of_visible_for_testing_member
      FlutterSecureStorage.setMockInitialValues({
        'ed25519_private_key': seed,
        'sound_enabled': '0',
      });
      final store = KeyStore();

      await store.resetIdentity();

      expect(await store.load(), isNull);
      expect(await store.loadSoundEnabled(), isFalse); // pref survives reset
    });
  });
}
