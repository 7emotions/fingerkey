// Test-runner entry point: delegates to the canonical lib/daemon_client_test.dart
// so `flutter test` discovers the v2 protocol client tests.
import 'package:auth/daemon_client_test.dart' as daemon_client_tests;

void main() => daemon_client_tests.main();
