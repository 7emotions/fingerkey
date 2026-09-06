package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// newKey generates a fresh Ed25519 keypair for tests.
func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// signDecision signs the pinned decision message for s with priv and returns
// the standard base64 signature for use in a /decision request body.
func signDecision(priv ed25519.PrivateKey, action string, s *Session) string {
	sig := ed25519.Sign(priv, signedMessage(action, s.User, s.Service, s.TTY, s.Nonce))
	return base64.StdEncoding.EncodeToString(sig)
}

// TestSignedMessageLayout pins the exact byte format:
//
//	"phone-fprint-auth/v1" || 0x00 || action || 0x00 ||
//	u8len(user)||user || u8len(service)||service || u8len(tty)||tty || nonce
//
// Length-prefixed fields are mandatory — raw concatenation would let
// "alice"/"sudo" collide with "al"/"icesudo".
func TestSignedMessageLayout(t *testing.T) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	got := signedMessage("approve", "alice", "sudo", "/dev/pts/0", nonce)

	want := []byte("phone-fprint-auth/v1")
	want = append(want, 0x00)
	want = append(want, "approve"...)
	want = append(want, 0x00)
	want = append(want, byte(len("alice")))
	want = append(want, "alice"...)
	want = append(want, byte(len("sudo")))
	want = append(want, "sudo"...)
	want = append(want, byte(len("/dev/pts/0")))
	want = append(want, "/dev/pts/0"...)
	want = append(want, nonce...) // raw 32 bytes, no length prefix

	if !bytes.Equal(got, want) {
		t.Fatalf("signedMessage layout mismatch:\n got  % x\n want % x", got, want)
	}
}

// TestSignedMessageEmptyTTY: an empty (canonicalized) tty still contributes
// its zero length byte — the field is never dropped.
func TestSignedMessageEmptyTTY(t *testing.T) {
	nonce := make([]byte, 32)

	got := signedMessage("deny", "bob", "su", "", nonce)

	want := []byte("phone-fprint-auth/v1")
	want = append(want, 0x00)
	want = append(want, "deny"...)
	want = append(want, 0x00)
	want = append(want, byte(len("bob")))
	want = append(want, "bob"...)
	want = append(want, byte(len("su")))
	want = append(want, "su"...)
	want = append(want, 0x00) // u8len(tty) == 0, zero bytes follow
	want = append(want, nonce...)

	if !bytes.Equal(got, want) {
		t.Fatalf("signedMessage empty-tty layout mismatch:\n got  % x\n want % x", got, want)
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv := newKey(t)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	msg := signedMessage("approve", "alice", "sudo", "", nonce)
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature over the pinned message must verify with its own public key")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	pubA, privA := newKey(t)
	pubB, _ := newKey(t)
	msg := signedMessage("approve", "alice", "sudo", "", make([]byte, 32))

	sig := ed25519.Sign(privA, msg)
	if !ed25519.Verify(pubA, msg, sig) {
		t.Fatal("sanity check: signature must verify with the signing key")
	}
	if ed25519.Verify(pubB, msg, sig) {
		t.Fatal("signature must NOT verify against a different key")
	}
}

func TestContextMismatch(t *testing.T) {
	_, priv := newKey(t)
	nonce := make([]byte, 32)

	// Signed over user "alice"...
	sig := ed25519.Sign(priv, signedMessage("approve", "alice", "sudo", "", nonce))
	// ...must not verify when the daemon rebuilds the message for "bob".
	if ed25519.Verify(priv.Public().(ed25519.PublicKey),
		signedMessage("approve", "bob", "sudo", "", nonce), sig) {
		t.Fatal("signature over user alice must not verify for user bob")
	}
}

func TestServiceMismatch(t *testing.T) {
	_, priv := newKey(t)
	nonce := make([]byte, 32)

	sig := ed25519.Sign(priv, signedMessage("approve", "alice", "sudo", "", nonce))
	if ed25519.Verify(priv.Public().(ed25519.PublicKey),
		signedMessage("approve", "alice", "pkexec", "", nonce), sig) {
		t.Fatal("signature over service sudo must not verify for service pkexec")
	}
}

func TestActionMismatch(t *testing.T) {
	_, priv := newKey(t)
	nonce := make([]byte, 32)

	sigApprove := ed25519.Sign(priv, signedMessage("approve", "alice", "sudo", "", nonce))
	if ed25519.Verify(priv.Public().(ed25519.PublicKey),
		signedMessage("deny", "alice", "sudo", "", nonce), sigApprove) {
		t.Fatal("an approve signature must not verify as a deny decision")
	}

	sigDeny := ed25519.Sign(priv, signedMessage("deny", "alice", "sudo", "", nonce))
	if ed25519.Verify(priv.Public().(ed25519.PublicKey),
		signedMessage("approve", "alice", "sudo", "", nonce), sigDeny) {
		t.Fatal("a deny signature must not verify as an approve decision")
	}
}
