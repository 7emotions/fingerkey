package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// waitNoLinks drains the link registry to zero so a later wait for THIS
// test's link is attributable to it alone.
func waitNoLinks(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		phoneLinks.Lock()
		n := len(phoneLinks.links)
		phoneLinks.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("stale phone links never unregistered")
		}
		time.Sleep(time.Millisecond)
	}
}

// dialPipeLink wires one phoneLink over a net.Pipe against store/kp and
// starts its run loop; the test acts as the phone on the returned pipe side.
// Tests that assert on global registry state (phoneConnected) call
// waitNoLinks themselves first.
func dialPipeLink(t *testing.T, store *Store, kp *keyProvider) (daemonSide, phoneSide net.Conn) {
	t.Helper()
	daemonSide, phoneSide = net.Pipe()
	go newPhoneLink(daemonSide).run(store, kp, nil)
	t.Cleanup(func() {
		daemonSide.Close()
		phoneSide.Close()
	})
	return daemonSide, phoneSide
}

// sendHello writes a hello frame carrying pub as the phone's public key.
func sendHello(t *testing.T, w io.Writer, pub ed25519.PublicKey) {
	t.Helper()
	hello := frameJSON(map[string]string{
		"type":   "hello",
		"pubkey": base64.StdEncoding.EncodeToString(pub),
		"name":   "test-phone",
	})
	if err := writeFrame(w, hello); err != nil {
		t.Fatalf("writeFrame(hello): %v", err)
	}
}

// readWelcome reads and decodes the next frame, expecting a welcome.
func readWelcome(t *testing.T, r io.Reader) welcomeFrame {
	t.Helper()
	payload, err := readFrame(r)
	if err != nil {
		t.Fatalf("readFrame(welcome): %v", err)
	}
	var w welcomeFrame
	if err := json.Unmarshal(payload, &w); err != nil {
		t.Fatalf("welcome frame is not valid JSON: %v", err)
	}
	if w.Type != "welcome" {
		t.Fatalf("type = %q, want %q", w.Type, "welcome")
	}
	return w
}

// handshakeRegistered performs the hello handshake with pub and fails unless
// the daemon answers a registered welcome; it returns that welcome.
func handshakeRegistered(t *testing.T, phoneSide net.Conn, pub ed25519.PublicKey) welcomeFrame {
	t.Helper()
	sendHello(t, phoneSide, pub)
	w := readWelcome(t, phoneSide)
	if !w.Registered {
		t.Fatalf("welcome = %+v, want registered:true", w)
	}
	return w
}

// startPipePhoneLink wires a phoneLink over a net.Pipe and completes the
// hello handshake with pub, so the link is registered, subscribed and the
// welcome is already consumed when it returns the phone side of the pipe.
func startPipePhoneLink(t *testing.T, store *Store, kp *keyProvider, pub ed25519.PublicKey) net.Conn {
	t.Helper()
	_, phoneSide := dialPipeLink(t, store, kp)
	handshakeRegistered(t, phoneSide, pub)
	return phoneSide
}

// TestPhoneLinkPendingFrame: on store.Create the pusher must emit one pending
// frame carrying the session id, the standard-base64 32-byte nonce, the
// user/service/tty context and the expires_at deadline (unix seconds).
func TestPhoneLinkPendingFrame(t *testing.T) {
	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	phone := startPipePhoneLink(t, store, kp, pub)

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
	if f.ExpiresAt != s.ExpiresAt.Unix() {
		t.Errorf("expires_at = %d, want %d", f.ExpiresAt, s.ExpiresAt.Unix())
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil {
		t.Fatalf("nonce %q is not standard base64: %v", f.Nonce, err)
	}
	if len(nonce) != 32 {
		t.Errorf("nonce decodes to %d bytes, want 32", len(nonce))
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
			kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
			phone := startPipePhoneLink(t, store, kp, pub)

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

// TestPhoneLinkBadMessage: a frame that is neither ping nor decision —
// malformed JSON or an unknown type — must yield
// {"type":"decision-result","id":"","error":"bad-message"}.
func TestPhoneLinkBadMessage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{name: "invalid JSON", payload: "this is not json"},
		{name: "unknown type", payload: `{"type":"garbage","id":"abc"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewStore()
			pub, _ := newKey(t)
			kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
			phone := startPipePhoneLink(t, store, kp, pub)

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

// TestPhoneLinkPingPong: a ping frame must be answered with a pong.
func TestPhoneLinkPingPong(t *testing.T) {
	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	phone := startPipePhoneLink(t, store, kp, pub)

	if err := writeFrame(phone, []byte(`{"type":"ping"}`)); err != nil {
		t.Fatalf("writeFrame(ping): %v", err)
	}
	payload, err := readFrame(phone)
	if err != nil {
		t.Fatalf("readFrame(pong): %v", err)
	}
	var pong pongFrame
	if err := json.Unmarshal(payload, &pong); err != nil {
		t.Fatalf("pong is not valid JSON: %v", err)
	}
	if pong.Type != "pong" {
		t.Errorf("type = %q, want %q", pong.Type, "pong")
	}
}

// TestPhoneLinkConnectedLifecycle: phoneConnected() must be true while a
// registered link is open and turn false after the phone side closes.
func TestPhoneLinkConnectedLifecycle(t *testing.T) {
	waitNoLinks(t)
	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	phone := startPipePhoneLink(t, store, kp, pub)

	if !phoneConnected() {
		t.Fatal("phoneConnected() = false while the registered link is open")
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

// TestPhoneLinkUnregistered: a hello whose pubkey is not paired must be
// answered with welcome{registered:false} and the link closed — no
// subscription, no pushes, no decision-results.
func TestPhoneLinkUnregistered(t *testing.T) {
	waitNoLinks(t)
	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	unpaired, _ := newKey(t)
	_, phoneSide := dialPipeLink(t, store, kp)

	sendHello(t, phoneSide, unpaired)
	w := readWelcome(t, phoneSide)
	if w.Registered {
		t.Fatalf("welcome = %+v, want registered:false", w)
	}
	if w.Key != "" {
		t.Errorf("key = %q, want empty on unregistered welcome", w.Key)
	}
	if len(w.Pending) != 0 {
		t.Errorf("unregistered welcome must carry no pending sessions, got %d", len(w.Pending))
	}
	if phoneConnected() {
		t.Fatal("phoneConnected() must be false for an unregistered link")
	}

	// The link is closed right after: a session created now must produce no
	// frame — the next read only ever sees the close.
	if _, err := store.Create("alice", "sudo", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	phoneSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFrame(phoneSide); err == nil {
		t.Fatal("unregistered link must receive nothing and be closed")
	}
}

// TestPhoneLinkUnregisteredNotCounted: many unregistered connections never
// flip phoneConnected() and never see pending sessions.
func TestPhoneLinkUnregisteredNotCounted(t *testing.T) {
	waitNoLinks(t)
	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	unpaired, _ := newKey(t)

	for i := 0; i < 8; i++ {
		_, phoneSide := dialPipeLink(t, store, kp)
		sendHello(t, phoneSide, unpaired)
		if w := readWelcome(t, phoneSide); w.Registered {
			t.Fatalf("link %d: welcome = %+v, want registered:false", i, w)
		}
		if phoneConnected() {
			t.Fatalf("phoneConnected() flipped true after %d unregistered links", i+1)
		}
		// Drain the close: the next read errors, and the link is gone.
		phoneSide.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := readFrame(phoneSide); err == nil {
			t.Fatalf("link %d: expected the unregistered link to be closed", i)
		}
	}

	if _, err := store.Create("alice", "sudo", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if phoneConnected() {
		t.Fatal("phoneConnected() must stay false after unregistered traffic")
	}
}

// TestPhoneLinkPreHelloTimeout: a connection that sends no hello within
// helloTimeout is dropped and never registers.
func TestPhoneLinkPreHelloTimeout(t *testing.T) {
	waitNoLinks(t)
	old := helloTimeout
	helloTimeout = 100 * time.Millisecond
	defer func() { helloTimeout = old }()

	store := NewStore()
	kp := newTestKeyProvider(t, nil)
	_, phoneSide := dialPipeLink(t, store, kp)

	// No hello is sent; the daemon side must close the pipe on its own.
	phoneSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFrame(phoneSide); err == nil {
		t.Fatal("expected the pre-hello link to be closed")
	}
	if phoneConnected() {
		t.Fatal("phoneConnected() must be false for a pre-hello link")
	}
}

// TestPhoneLinkIdleTimeout: a registered link that goes silent (no frame at
// all) is closed after linkIdleTimeout and unregistered — the half-open
// defense.
func TestPhoneLinkIdleTimeout(t *testing.T) {
	waitNoLinks(t)
	old := linkIdleTimeout
	linkIdleTimeout = 100 * time.Millisecond
	defer func() { linkIdleTimeout = old }()

	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	phone := startPipePhoneLink(t, store, kp, pub)

	if !phoneConnected() {
		t.Fatal("phoneConnected() = false while the link is open")
	}

	// Silent link: the daemon must drop it on its own.
	phone.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFrame(phone); err == nil {
		t.Fatal("expected the idle link to be closed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for phoneConnected() {
		if time.Now().After(deadline) {
			t.Fatal("phoneConnected() still true after the idle link was dropped")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPhoneLinkPingKeepsAlive: a link pinging inside the idle window stays
// alive (every frame resets the timer), and dies once the pings stop.
func TestPhoneLinkPingKeepsAlive(t *testing.T) {
	waitNoLinks(t)
	old := linkIdleTimeout
	linkIdleTimeout = 300 * time.Millisecond
	defer func() { linkIdleTimeout = old }()

	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	phone := startPipePhoneLink(t, store, kp, pub)

	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := writeFrame(phone, []byte(`{"type":"ping"}`)); err != nil {
			t.Fatalf("ping %d: writeFrame: %v", i, err)
		}
		phone.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := readFrame(phone); err != nil {
			t.Fatalf("ping %d: readFrame(pong): %v", i, err)
		}
		if !phoneConnected() {
			t.Fatal("phoneConnected() = false while the link is pinging")
		}
	}

	// Pings stop: the idle timer must now reap the link.
	deadline := time.Now().Add(5 * time.Second)
	for phoneConnected() {
		if time.Now().After(deadline) {
			t.Fatal("phoneConnected() still true after pings stopped")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTwoLinksFirstComeFirstServed: two registered links on the same session
// — the first decision wins; the second decision is an idempotent replay
// returning the first link's outcome, and both links receive the
// decision-result.
func TestTwoLinksFirstComeFirstServed(t *testing.T) {
	store := NewStore()
	pubAlice, privAlice := newKey(t)
	pubBob, privBob := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pubAlice, "bob": pubBob})

	linkAlice := startPipePhoneLink(t, store, kp, pubAlice)
	linkBob := startPipePhoneLink(t, store, kp, pubBob)

	s, err := store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Both links receive the pending push.
	for _, link := range []net.Conn{linkAlice, linkBob} {
		payload, err := readFrame(link)
		if err != nil {
			t.Fatalf("readFrame(pending): %v", err)
		}
		var f pendingFrame
		if err := json.Unmarshal(payload, &f); err != nil {
			t.Fatalf("pending frame is not valid JSON: %v", err)
		}
		if f.ID != s.ID {
			t.Errorf("pending id = %q, want %q", f.ID, s.ID)
		}
	}

	// Alice approves first.
	decision, err := json.Marshal(map[string]string{
		"type":     "decision",
		"id":       s.ID,
		"decision": "approve",
		"sig":      signDecision(privAlice, "approve", s),
	})
	if err != nil {
		t.Fatalf("marshal decision: %v", err)
	}
	if err := writeFrame(linkAlice, decision); err != nil {
		t.Fatalf("writeFrame(decision): %v", err)
	}

	// Both links receive the approved decision-result naming alice.
	for _, link := range []net.Conn{linkAlice, linkBob} {
		payload, err := readFrame(link)
		if err != nil {
			t.Fatalf("readFrame(result): %v", err)
		}
		var res decisionResultFrame
		if err := json.Unmarshal(payload, &res); err != nil {
			t.Fatalf("result is not valid JSON: %v", err)
		}
		if res.Type != "decision-result" || res.ID != s.ID || res.Status != StatusApproved || res.Key != "alice" {
			t.Errorf("result = %+v, want approved decision-result by alice", res)
		}
	}

	// Bob's later deny is an idempotent replay: alice's outcome comes back.
	decision, err = json.Marshal(map[string]string{
		"type":     "decision",
		"id":       s.ID,
		"decision": "deny",
		"sig":      signDecision(privBob, "deny", s),
	})
	if err != nil {
		t.Fatalf("marshal replay: %v", err)
	}
	if err := writeFrame(linkBob, decision); err != nil {
		t.Fatalf("writeFrame(replay): %v", err)
	}
	payload, err := readFrame(linkBob)
	if err != nil {
		t.Fatalf("readFrame(replay result): %v", err)
	}
	var res decisionResultFrame
	if err := json.Unmarshal(payload, &res); err != nil {
		t.Fatalf("replay result is not valid JSON: %v", err)
	}
	if res.Status != StatusApproved || res.Key != "alice" {
		t.Errorf("replay result = %+v, want approved by alice (first decision wins)", res)
	}

	if s.DecidedBy != "alice" {
		t.Errorf("DecidedBy = %q, want %q", s.DecidedBy, "alice")
	}
}

// TestWelcomeSnapshotPending: the welcome control frame carries the snapshot
// of sessions pending before the hello, and a session created after the
// handshake arrives as a live push.
func TestWelcomeSnapshotPending(t *testing.T) {
	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})

	first, err := store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	second, err := store.Create("bob", "su", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, phoneSide := dialPipeLink(t, store, kp)
	w := handshakeRegistered(t, phoneSide, pub)
	if len(w.Pending) != 2 {
		t.Fatalf("welcome.Pending = %d sessions, want 2", len(w.Pending))
	}
	if w.Pending[0].ID != first.ID || w.Pending[1].ID != second.ID {
		t.Errorf("welcome.Pending = %q, %q; want %q, %q (oldest first)",
			w.Pending[0].ID, w.Pending[1].ID, first.ID, second.ID)
	}
	if w.Pending[0].ExpiresAt != first.ExpiresAt.Unix() {
		t.Errorf("welcome.Pending[0].expires_at = %d, want %d", w.Pending[0].ExpiresAt, first.ExpiresAt.Unix())
	}

	third, err := store.Create("carol", "pkexec", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	payload, err := readFrame(phoneSide)
	if err != nil {
		t.Fatalf("readFrame(live push): %v", err)
	}
	var f pendingFrame
	if err := json.Unmarshal(payload, &f); err != nil {
		t.Fatalf("live push is not valid JSON: %v", err)
	}
	if f.ID != third.ID {
		t.Errorf("live push id = %q, want %q", f.ID, third.ID)
	}
}

// TestPushQueueDropOnFull: when the phone stops reading, the bounded push
// queue overflows and the overflow is audited as push-dropped — never a
// panic, never a silent drop.
func TestPushQueueDropOnFull(t *testing.T) {
	buf := swapAudit(t)
	waitNoLinks(t)
	store := NewStore()
	pub, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	phone := startPipePhoneLink(t, store, kp, pub)

	// Prime the link: one session fully delivered proves the pusher and
	// writer goroutines are draining.
	if _, err := store.Create("alice", "sudo", ""); err != nil {
		t.Fatalf("prime Create: %v", err)
	}
	if _, err := readFrame(phone); err != nil {
		t.Fatalf("readFrame(prime pending): %v", err)
	}

	// The phone reads nothing from here on: the writer blocks on the first
	// pending frame and the queue fills up. The inter-create pause lets the
	// pusher drain the store channel between deliveries, so the overflow
	// happens at the bounded queue — the audited seam.
	for i := 0; i < 12; i++ {
		if _, err := store.Create("alice", "sudo", ""); err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}

	// The overflow must surface as audited push-dropped lines. Reads take
	// auditMu because the pusher goroutine writes to the same buffer.
	deadline := time.Now().Add(5 * time.Second)
	for {
		auditMu.Lock()
		got := buf.String()
		auditMu.Unlock()
		if strings.Contains(got, "event=push-dropped") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("push-dropped audit line never appeared")
		}
		time.Sleep(time.Millisecond)
	}

	// Cleanup sanity: the link is still alive (drop, not kill) until closed.
	if !phoneConnected() {
		t.Fatal("phoneConnected() = false after queue overflow; the link must survive drops")
	}
	phone.Close()
}

// TestPhoneLinkUnregisteredNoDecisionResult: a decision result is never
// delivered to an unregistered link.
func TestPhoneLinkUnregisteredNoDecisionResult(t *testing.T) {
	waitNoLinks(t)
	store := NewStore()
	pubAlice, privAlice := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pubAlice})
	unpaired, _ := newKey(t)

	// Unregistered link: welcome{registered:false} and closed.
	_, unregisteredPhone := dialPipeLink(t, store, kp)
	sendHello(t, unregisteredPhone, unpaired)
	if w := readWelcome(t, unregisteredPhone); w.Registered {
		t.Fatalf("welcome = %+v, want registered:false", w)
	}

	// Registered link decides a session; the unregistered link must see
	// nothing of it — only its own close.
	linkAlice := startPipePhoneLink(t, store, kp, pubAlice)
	s, err := store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := readFrame(linkAlice); err != nil {
		t.Fatalf("readFrame(pending): %v", err)
	}
	decision := frameJSON(map[string]string{
		"type":     "decision",
		"id":       s.ID,
		"decision": "approve",
		"sig":      signDecision(privAlice, "approve", s),
	})
	if err := writeFrame(linkAlice, decision); err != nil {
		t.Fatalf("writeFrame(decision): %v", err)
	}
	if _, err := readFrame(linkAlice); err != nil {
		t.Fatalf("readFrame(result): %v", err)
	}

	unregisteredPhone.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFrame(unregisteredPhone); err == nil {
		t.Fatal("unregistered link received a frame; want none")
	}
}
