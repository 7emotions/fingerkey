package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSimSocketEndToEnd proves servePhoneSimSocket + startPhoneLink work over
// a real unix socket exactly as main() wires them: a stale socket file is
// replaced, the accepted stream gets a pending frame on store.Create, and a
// signed decision frame is answered with a decision-result.
func TestSimSocketEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sim.sock")
	// Stale socket from a previous run: Listen must not fail, proving the
	// remove-first step works.
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatalf("WriteFile stale: %v", err)
	}

	store := NewStore()
	pub, priv := newKey(t)
	keys := map[string]ed25519.PublicKey{"alice": pub}

	ln, err := servePhoneSimSocket(path, store, keys)
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

	// Wait until the accepted link is registered: run() subscribes before
	// registering, so a Create after this cannot be missed.
	deadline := time.Now().Add(5 * time.Second)
	for !phoneConnected() {
		if time.Now().After(deadline) {
			t.Fatal("sim-socket link did not register")
		}
		time.Sleep(time.Millisecond)
	}

	s, err := store.Create("alice", "sudo", "/dev/pts/0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The pusher must emit one pending frame with the session context.
	payload, err := readFrame(conn)
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
}
