package format

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// testNonce returns a deterministic 32-byte nonce filled with b.
func testNonce(b byte) []byte {
	n := make([]byte, 32)
	for i := range n {
		n[i] = b
	}
	return n
}

// TestSignedMessageLayout pins the exact byte layout of the message that must
// be signed (and that the daemon rebuilds to verify):
//
//	"phone-fprint-auth/v1" || 0x00 || action || 0x00 ||
//	u8len(user)||user || u8len(service)||service || u8len(tty)||tty || nonce
//
// The expected bytes are written out manually — they must NOT be produced by
// calling SignedMessage itself, so a broken implementation fails the test.
func TestSignedMessageLayout(t *testing.T) {
	nonce := testNonce(0x42)
	got := SignedMessage("approve", "alice", "sudo", "", nonce)

	want := append([]byte("phone-fprint-auth/v1\x00approve\x00\x05alice\x04sudo\x00"), nonce...)
	if !bytes.Equal(got, want) {
		t.Fatalf("layout mismatch:\n got: %x\nwant: %x", got, want)
	}
}

// TestSignedMessageLayoutWithTTY pins the layout with a non-empty tty: its
// single-byte length prefix (0x0a for "/dev/pts/0") must be present.
func TestSignedMessageLayoutWithTTY(t *testing.T) {
	nonce := testNonce(0x00)
	got := SignedMessage("deny", "bob", "pkexec", "/dev/pts/0", nonce)

	want := append([]byte("phone-fprint-auth/v1\x00deny\x00\x03bob\x06pkexec\x0a/dev/pts/0"), nonce...)
	if !bytes.Equal(got, want) {
		t.Fatalf("layout mismatch:\n got: %x\nwant: %x", got, want)
	}
}

// TestLengthPrefixesDisambiguate: without length prefixes "alice"+"sudo" would
// collide with "al"+"icesudo" — the prefix bytes must prevent that.
func TestLengthPrefixesDisambiguate(t *testing.T) {
	nonce := testNonce(0x01)
	a := SignedMessage("approve", "alice", "sudo", "", nonce)
	b := SignedMessage("approve", "al", "icesudo", "", nonce)
	if bytes.Equal(a, b) {
		t.Fatal("messages with concatenated-equal fields must differ")
	}
}

// TestGenerateKeySignVerify roundtrips: GenerateKey produces a usable keypair,
// Sign produces a signature the daemon would verify over the pinned message,
// and a tampered message fails verification.
func TestGenerateKeySignVerify(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("private key does not correspond to public key")
	}

	nonce := testNonce(0x07)
	msg := SignedMessage("approve", "alice", "sudo", "", nonce)
	sig := Sign(priv, msg)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature over the pinned message must verify")
	}
	if ed25519.Verify(pub, append(append([]byte{}, msg...), 0x00), sig) {
		t.Fatal("signature must not verify over a tampered message")
	}
}
