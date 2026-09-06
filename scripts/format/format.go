// Package format implements the pinned signed-message format shared by the C
// PAM module, the Go daemon, this Go simulator, and the Dart app.
//
// The exact byte string that must be signed (and, on the daemon side,
// rebuilt and verified) for every decision is:
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
package format

import (
	"crypto/ed25519"
	"crypto/rand"
)

// SignedMessage builds the exact byte string that must be signed for a
// decision. It replicates, byte for byte, the daemon's signedMessage so that
// every implementation signs and verifies the same bytes.
func SignedMessage(action, user, service, tty string, nonce []byte) []byte {
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

// GenerateKey generates a fresh Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign returns the Ed25519 signature of msg with priv.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}
