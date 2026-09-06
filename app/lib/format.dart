/// Byte-level format shared with the Go daemon (daemon/crypto.go).
///
/// Every decision is signed over:
///
///   "phone-fprint-auth/v1" || 0x00 || action || 0x00 ||
///   u8len(user)||user || u8len(service)||service || u8len(tty)||tty || nonce
///
/// where:
///   - action is "approve" or "deny" (ASCII, no length byte);
///   - u8len(x) is a SINGLE byte length prefix (0-255);
///   - tty is "" when empty (u8len 0);
///   - nonce is the raw 32 bytes (no length prefix).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

const String kDomainSeparator = 'phone-fprint-auth/v1';
const String kActionApprove = 'approve';
const String kActionDeny = 'deny';

/// Builds the exact byte string the daemon rebuilds and verifies.
///
/// Byte-identical to Go's `signedMessage(action, user, service, tty, nonce)`.
Uint8List signedMessage(
  String action,
  String user,
  String service,
  String tty,
  Uint8List nonce,
) {
  final userBytes = utf8.encode(user);
  final serviceBytes = utf8.encode(service);
  final ttyBytes = utf8.encode(tty);
  assert(userBytes.length <= 255);
  assert(serviceBytes.length <= 255);
  assert(ttyBytes.length <= 255);

  final builder = BytesBuilder(copy: false);
  builder.add(utf8.encode(kDomainSeparator));
  builder.addByte(0x00);
  builder.add(utf8.encode(action));
  builder.addByte(0x00);
  builder.addByte(userBytes.length);
  builder.add(userBytes);
  builder.addByte(serviceBytes.length);
  builder.add(serviceBytes);
  builder.addByte(ttyBytes.length);
  builder.add(ttyBytes);
  builder.add(nonce);
  return builder.toBytes();
}

/// Signs a decision with the device's Ed25519 key and returns the
/// base64 (standard, padded) signature for `POST /v1/session/{id}/decision`.
Future<String> signDecision({
  required SimpleKeyPair keyPair,
  required String action,
  required String user,
  required String service,
  required String tty,
  required Uint8List nonce,
}) async {
  final message = signedMessage(action, user, service, tty, nonce);
  final signature = await Ed25519().sign(message, keyPair: keyPair);
  return base64.encode(signature.bytes);
}
