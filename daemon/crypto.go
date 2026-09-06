package main

// signedMessage builds the exact byte string that MUST be signed (and, on the
// daemon side, rebuilt and verified) for every decision. The format is pinned
// so the C PAM module, Go daemon, Go phone-simulator, and Dart app all agree:
//
//	"phone-fprint-auth/v1" || 0x00 || action || 0x00 ||
//	u8len(user)||user || u8len(service)||service || u8len(tty)||tty || nonce
//
// where:
//   - action is "approve" or "deny" (ASCII, no length byte);
//   - u8len(x) is a SINGLE byte length prefix (0-255) — the length prefixes
//     make the concatenation unambiguous (raw concatenation would let
//     "alice"+"sudo" collide with "al"+"icesudo");
//   - tty is already canonicalized ("" when empty, so u8len(tty) is 0);
//   - nonce is the raw 32 bytes (no length prefix).
//
// The leading constant is the domain separator: a signature here cannot be
// replayed against any other protocol (or future version of this one).
func signedMessage(action, user, service, tty string, nonce []byte) []byte {
	msg := make([]byte, 0, 22+len(action)+len(user)+len(service)+len(tty)+len(nonce))
	msg = append(msg, "phone-fprint-auth/v1"...)
	msg = append(msg, 0x00)
	msg = append(msg, action...)
	msg = append(msg, 0x00)
	msg = append(msg, byte(len(user)))
	msg = append(msg, user...)
	msg = append(msg, byte(len(service)))
	msg = append(msg, service...)
	msg = append(msg, byte(len(tty)))
	msg = append(msg, tty...)
	msg = append(msg, nonce...)
	return msg
}
