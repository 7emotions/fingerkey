package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSimSocketEndToEnd proves servePhoneSimSocket + startPhoneLink work over
// a real unix socket exactly as main() wires them: a stale socket file is
// replaced, the accepted stream answers a hello with a registered welcome,
// gets a pending frame on store.Create, and a signed decision frame is
// answered with a decision-result.
func TestSimSocketEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sim.sock")
	// Stale socket from a previous run: Listen must not fail, proving the
	// remove-first step works.
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatalf("WriteFile stale: %v", err)
	}

	store := NewStore()
	pub, priv := newKey(t)
	keys := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})

	ln, err := servePhoneSimSocket(path, store, keys, nil)
	if err != nil {
		t.Fatalf("servePhoneSimSocket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	if fi, err := os.Stat(path); err != nil {
		t.Fatalf("stat socket: %v", err)
	} else if fi.Mode().Perm() != 0700 {
		t.Errorf("socket mode = %v, want 0700", fi.Mode().Perm())
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// The v2 handshake: hello with the paired pubkey must be answered with a
	// registered welcome before any push.
	hello, err := json.Marshal(map[string]string{
		"type":   "hello",
		"pubkey": base64.StdEncoding.EncodeToString(pub),
		"name":   "sim-phone",
	})
	if err != nil {
		t.Fatalf("marshal hello: %v", err)
	}
	if err := writeFrame(conn, hello); err != nil {
		t.Fatalf("writeFrame(hello): %v", err)
	}
	payload, err := readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame(welcome): %v", err)
	}
	var welcome welcomeFrame
	if err := json.Unmarshal(payload, &welcome); err != nil {
		t.Fatalf("welcome frame is not valid JSON: %v", err)
	}
	if !welcome.Registered || welcome.Key != "alice" {
		t.Fatalf("welcome = %+v, want registered key alice", welcome)
	}

	s, err := store.Create("alice", "sudo", "/dev/pts/0", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The pusher must emit one pending frame with the session context.
	payload, err = readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame(pending): %v", err)
	}
	var f pendingFrame
	if err := json.Unmarshal(payload, &f); err != nil {
		t.Fatalf("pending frame is not valid JSON: %v", err)
	}
	if f.Type != "pending" || f.ID != s.ID || f.User != "alice" || f.Service != "sudo" || f.TTY != "/dev/pts/0" {
		t.Errorf("pending frame = %+v, want the created session", f)
	}
	if f.ExpiresAt != s.ExpiresAt.Unix() {
		t.Errorf("expires_at = %d, want %d", f.ExpiresAt, s.ExpiresAt.Unix())
	}

	// A signed decision frame must be answered with an approved result.
	decision, err := json.Marshal(map[string]string{
		"type":     "decision",
		"id":       s.ID,
		"decision": "approve",
		"sig":      signDecision(priv, "approve", s),
	})
	if err != nil {
		t.Fatalf("marshal decision: %v", err)
	}
	if err := writeFrame(conn, decision); err != nil {
		t.Fatalf("writeFrame(decision): %v", err)
	}
	payload, err = readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame(result): %v", err)
	}
	var res decisionResultFrame
	if err := json.Unmarshal(payload, &res); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if res.Type != "decision-result" || res.ID != s.ID || res.Status != StatusApproved || res.Key != "alice" {
		t.Errorf("result = %+v, want approved decision-result for alice", res)
	}
	if s.Status != StatusApproved {
		t.Errorf("session status = %q, want %q", s.Status, StatusApproved)
	}
	if s.DecidedBy != "alice" {
		t.Errorf("DecidedBy = %q, want %q", s.DecidedBy, "alice")
	}
}

// TestSimSocketUnregisteredHello: a hello with an unpaired pubkey must be
// answered with welcome{registered:false} and the link closed — and it must
// not register the link for phoneConnected().
func TestSimSocketUnregisteredHello(t *testing.T) {
	waitNoLinks(t)
	path := filepath.Join(t.TempDir(), "sim.sock")
	store := NewStore()
	unpaired, _ := newKey(t)

	ln, err := servePhoneSimSocket(path, store, newTestKeyProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("servePhoneSimSocket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	hello, err := json.Marshal(map[string]string{
		"type":   "hello",
		"pubkey": base64.StdEncoding.EncodeToString(unpaired),
		"name":   "sim-phone",
	})
	if err != nil {
		t.Fatalf("marshal hello: %v", err)
	}
	if err := writeFrame(conn, hello); err != nil {
		t.Fatalf("writeFrame(hello): %v", err)
	}
	payload, err := readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame(welcome): %v", err)
	}
	var welcome welcomeFrame
	if err := json.Unmarshal(payload, &welcome); err != nil {
		t.Fatalf("welcome frame is not valid JSON: %v", err)
	}
	if welcome.Registered {
		t.Fatalf("welcome = %+v, want registered:false", welcome)
	}
	if len(welcome.Pending) != 0 {
		t.Errorf("unregistered welcome must carry no pending sessions, got %d", len(welcome.Pending))
	}
	if phoneConnected() {
		t.Fatal("phoneConnected() must be false for an unregistered hello")
	}

	// The link must be closed right after: the next read sees EOF.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFrame(conn); err == nil {
		t.Fatal("expected the unregistered link to be closed")
	}
}
