package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// startPhoneLink wires one phoneLink over a net.Pipe against store/keys,
// starts its run loop, and waits until THIS link is registered. run subscribes
// before registering, so once the counter has moved the subscription is
// already active: a Create immediately afterwards cannot be missed.
// It returns the phone side of the pipe; the test acts as the phone.
func startPhoneLink(t *testing.T, store *Store, keys map[string]ed25519.PublicKey) net.Conn {
	t.Helper()

	// A previous link's unregister is deferred and therefore asynchronous to
	// its cleanup's pipe close: first drain the counter back to zero so the
	// wait below is attributable to THIS link alone.
	deadline := time.Now().Add(5 * time.Second)
	for {
		phoneLinks.Lock()
		active := phoneLinks.active
		phoneLinks.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stale phone link never unregistered")
		}
		time.Sleep(time.Millisecond)
	}

	daemonSide, phoneSide := net.Pipe()
	l := &phoneLink{rwc: daemonSide}
	go l.run(store, keys)
	t.Cleanup(func() {
		daemonSide.Close()
		phoneSide.Close()
	})

	deadline = time.Now().Add(5 * time.Second)
	for {
		phoneLinks.Lock()
		active := phoneLinks.active
		phoneLinks.Unlock()
		if active > 0 {
			return phoneSide
		}
		if time.Now().After(deadline) {
			t.Fatal("phone link did not register")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPhoneLinkPendingFrame: on store.Create the pusher must emit one pending
// frame carrying the session id, the standard-base64 32-byte nonce, and the
// user/service/tty context.
func TestPhoneLinkPendingFrame(t *testing.T) {
	store := NewStore()
	phone := startPhoneLink(t, store, nil)

	s, err := store.Create("alice", "sudo", "/dev/pts/0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	payload, err := readFrame(phone)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	var f pendingFrame
	if err := json.Unmarshal(payload, &f); err != nil {
		t.Fatalf("pending frame is not valid JSON: %v", err)
	}
	if f.Type != "pending" {
		t.Errorf("type = %q, want %q", f.Type, "pending")
	}
	if f.ID != s.ID {
		t.Errorf("id = %q, want %q", f.ID, s.ID)
	}
	if f.User != "alice" || f.Service != "sudo" || f.TTY != "/dev/pts/0" {
		t.Errorf("context = %q/%q/%q, want alice/sudo//dev/pts/0", f.User, f.Service, f.TTY)
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil {
		t.Fatalf("nonce %q is not standard base64: %v", f.Nonce, err)
	}
	if len(nonce) != 32 {
		t.Errorf("nonce decodes to %d bytes, want 32", len(nonce))
	}
	if !bytes.Equal(nonce, s.Nonce) {
		t.Errorf("nonce mismatch: got %x, want %x", nonce, s.Nonce)
	}
}

// TestPhoneLinkDecision: a signed decision frame must yield a decision-result
// with the resulting status and the paired key name — approved for approve,
// denied for deny.
func TestPhoneLinkDecision(t *testing.T) {
	for _, tc := range []struct {
		decision string
		want     string
	}{
		{decision: "approve", want: StatusApproved},
		{decision: "deny", want: StatusDenied},
	} {
		t.Run(tc.decision, func(t *testing.T) {
			store := NewStore()
			pub, priv := newKey(t)
			keys := map[string]ed25519.PublicKey{"alice": pub}
			phone := startPhoneLink(t, store, keys)

			s, err := store.Create("alice", "sudo", "")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			// Drain the pusher's pending frame first: net.Pipe writes block
			// until read, and the frames are strictly ordered.
			if _, err := readFrame(phone); err != nil {
				t.Fatalf("drain pending frame: %v", err)
			}

			decision, err := json.Marshal(map[string]string{
				"type":     "decision",
				"id":       s.ID,
				"decision": tc.decision,
				"sig":      signDecision(priv, tc.decision, s),
			})
			if err != nil {
				t.Fatalf("marshal decision: %v", err)
			}
			if err := writeFrame(phone, decision); err != nil {
				t.Fatalf("writeFrame(decision): %v", err)
			}

			payload, err := readFrame(phone)
			if err != nil {
				t.Fatalf("readFrame(result): %v", err)
			}
			var res decisionResultFrame
			if err := json.Unmarshal(payload, &res); err != nil {
				t.Fatalf("result is not valid JSON: %v", err)
			}
			if res.Type != "decision-result" {
				t.Errorf("type = %q, want %q", res.Type, "decision-result")
			}
			if res.ID != s.ID {
				t.Errorf("id = %q, want %q", res.ID, s.ID)
			}
			if res.Status != tc.want {
				t.Errorf("status = %q, want %q", res.Status, tc.want)
			}
			if res.Key != "alice" {
				t.Errorf("key = %q, want %q", res.Key, "alice")
			}
			if res.Error != "" {
				t.Errorf("error = %q, want empty on success", res.Error)
			}
		})
	}
}

// TestPhoneLinkBadMessage: a frame that is not a decision — malformed JSON or
// an unknown type — must yield {"type":"decision-result","id":"","error":"bad-message"}.
func TestPhoneLinkBadMessage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{name: "invalid JSON", payload: "this is not json"},
		{name: "unknown type", payload: `{"type":"ping","id":"abc"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewStore()
			phone := startPhoneLink(t, store, nil)

			if err := writeFrame(phone, []byte(tc.payload)); err != nil {
				t.Fatalf("writeFrame: %v", err)
			}

			payload, err := readFrame(phone)
			if err != nil {
				t.Fatalf("readFrame(result): %v", err)
			}
			var res decisionResultFrame
			if err := json.Unmarshal(payload, &res); err != nil {
				t.Fatalf("result is not valid JSON: %v", err)
			}
			if res.Type != "decision-result" {
				t.Errorf("type = %q, want %q", res.Type, "decision-result")
			}
			if res.ID != "" {
				t.Errorf("id = %q, want empty on a bad message", res.ID)
			}
			if res.Error != "bad-message" {
				t.Errorf("error = %q, want %q", res.Error, "bad-message")
			}
		})
	}
}

// TestPhoneLinkConnectedLifecycle: phoneConnected() must be true while the
// link is open and turn false after the phone side closes.
func TestPhoneLinkConnectedLifecycle(t *testing.T) {
	store := NewStore()
	phone := startPhoneLink(t, store, nil)

	if !phoneConnected() {
		t.Fatal("phoneConnected() = false while the link is open")
	}

	if err := phone.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for phoneConnected() {
		if time.Now().After(deadline) {
			t.Fatal("phoneConnected() still true after the link closed")
		}
		time.Sleep(time.Millisecond)
	}
}
