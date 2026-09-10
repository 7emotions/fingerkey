package main

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---- Store.Subscribe broadcast tests ----

// TestStoreSubscribeBroadcast: two subscribers must EACH receive every
// Create (broadcast, not consume).
func TestStoreSubscribeBroadcast(t *testing.T) {
	st := NewStore()
	ch1, unsub1 := st.Subscribe()
	defer unsub1()
	ch2, unsub2 := st.Subscribe()
	defer unsub2()

	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i, ch := range []<-chan *Session{ch1, ch2} {
		select {
		case got := <-ch:
			if got != s {
				t.Errorf("subscriber %d got %q, want the created session %q", i, got.ID, s.ID)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d did not receive the created session", i)
		}
	}
}

// TestStoreSubscribeUnsubscribe: after unsubscribing, a subscriber must not
// receive further Creates; the unsubscribe closure is idempotent.
func TestStoreSubscribeUnsubscribe(t *testing.T) {
	st := NewStore()
	ch, unsub := st.Subscribe()

	unsub()
	unsub() // idempotent: second call must not panic

	if _, err := st.Create("alice", "sudo", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	select {
	case s := <-ch:
		t.Fatalf("unsubscribed subscriber still received session %q", s.ID)
	case <-time.After(100 * time.Millisecond):
		// expected: nothing delivered after unsubscribe
	}
}

// TestStoreSubscribeSkipWhenFull: delivery is non-blocking — when a
// subscriber's one-slot buffer is full, that Create is skipped and the
// subscriber keeps the earlier session.
func TestStoreSubscribeSkipWhenFull(t *testing.T) {
	st := NewStore()
	ch, unsub := st.Subscribe()
	defer unsub()

	first, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	second, err := st.Create("bob", "su", "")
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("sanity: two Creates must yield distinct ids")
	}

	// The buffer still holds `first`; the second Create must have been
	// skipped rather than blocking or dropping the earlier delivery.
	select {
	case got := <-ch:
		if got != first {
			t.Fatalf("subscriber got %q, want the first session %q", got.ID, first.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive the first session")
	}
	select {
	case s := <-ch:
		t.Fatalf("subscriber received %q after the skip, want only the first session", s.ID)
	case <-time.After(100 * time.Millisecond):
		// expected: the full-buffer Create was skipped
	}
}

// ---- decide() tests ----

// testDecideStore builds a store with one pending session and a keyProvider
// holding the paired pubkey under the name "alice".
func testDecideStore(t *testing.T) (*Store, *keyProvider, ed25519.PrivateKey, *Session) {
	t.Helper()
	store := NewStore()
	pub, priv := newKey(t)
	keys := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})
	s, err := store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return store, keys, priv, s
}

func TestDecideApprove(t *testing.T) {
	store, keys, priv, s := testDecideStore(t)

	code, status, key := decide(store, keys, s.ID, "approve", signDecision(priv, "approve", s))
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if status != StatusApproved {
		t.Errorf("status = %q, want %q", status, StatusApproved)
	}
	if key != "alice" {
		t.Errorf("key = %q, want %q (paired key name)", key, "alice")
	}
	if s.Status != StatusApproved {
		t.Errorf("session status = %q, want %q", s.Status, StatusApproved)
	}
}

func TestDecideDenyMapping(t *testing.T) {
	store, keys, priv, s := testDecideStore(t)

	code, status, key := decide(store, keys, s.ID, "deny", signDecision(priv, "deny", s))
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if status != StatusDenied {
		t.Errorf("status = %q, want %q", status, StatusDenied)
	}
	if key != "alice" {
		t.Errorf("key = %q, want %q", key, "alice")
	}
}

func TestDecideBadDecision(t *testing.T) {
	store, keys, _, s := testDecideStore(t)

	code, _, _ := decide(store, keys, s.ID, "maybe", "")
	if code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
	if s.Status != StatusPending {
		t.Fatalf("session status = %q, want %q (unchanged)", s.Status, StatusPending)
	}
}

func TestDecideWrongKey(t *testing.T) {
	store, keys, _, s := testDecideStore(t)
	_, otherPriv := newKey(t) // unpaired key

	code, _, key := decide(store, keys, s.ID, "approve", signDecision(otherPriv, "approve", s))
	if code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", code)
	}
	if key != "" {
		t.Errorf("key = %q, want empty on failure", key)
	}
	if s.Status != StatusPending {
		t.Fatalf("session status = %q, want %q (unchanged)", s.Status, StatusPending)
	}
}

// TestDecideTwice: deciding an already-decided session is an idempotent
// replay, not a conflict — the second decide returns the original outcome
// and the key that produced it.
func TestDecideTwice(t *testing.T) {
	store, keys, priv, s := testDecideStore(t)

	sig := signDecision(priv, "approve", s)
	if code, _, _ := decide(store, keys, s.ID, "approve", sig); code != http.StatusOK {
		t.Fatalf("first decide code = %d, want 200", code)
	}
	code, status, key := decide(store, keys, s.ID, "approve", sig)
	if code != http.StatusOK {
		t.Fatalf("second decide code = %d, want 200 (idempotent replay)", code)
	}
	if status != StatusApproved {
		t.Errorf("second decide status = %q, want %q (original outcome)", status, StatusApproved)
	}
	if key != "alice" {
		t.Errorf("second decide key = %q, want %q (DecidedBy)", key, "alice")
	}
}

// TestDecideExpiredSession: deciding an expired session reports the expired
// status as a success, never a 409.
func TestDecideExpiredSession(t *testing.T) {
	old := sessionTTL
	sessionTTL = 20 * time.Millisecond
	defer func() { sessionTTL = old }()

	store, keys, priv, s := testDecideStore(t)
	time.Sleep(50 * time.Millisecond)

	code, status, _ := decide(store, keys, s.ID, "approve", signDecision(priv, "approve", s))
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (expired is not an error)", code)
	}
	if status != StatusExpired {
		t.Errorf("status = %q, want %q", status, StatusExpired)
	}
}

func TestDecideUnknown(t *testing.T) {
	store, keys, priv, _ := testDecideStore(t)

	// A well-formed signature over some session must still 404 on an
	// unknown id (the id check runs before verification).
	fake := &Session{Nonce: make([]byte, 32), User: "x", Service: "y", TTY: ""}
	code, _, _ := decide(store, keys, "doesnotexist", "approve", signDecision(priv, "approve", fake))
	if code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", code)
	}
}

// TestDecideNoPhoneLink503: with paired keys but NO active phone link, a
// session create on the local mux must fail fast with 503 so the PAM module
// falls back to the password prompt instead of polling a request no phone
// can approve.
func TestDecideNoPhoneLink503(t *testing.T) {
	// No registered phone link here: no linkPhone(t) call.
	store := NewStore()
	pub, _ := newKey(t)
	local := httptest.NewServer(newLocalMux(store, newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub}), nil))
	defer local.Close()

	resp := postJSON(t, local.URL+"/v1/session", `{"user":"alice","service":"sudo"}`)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (no phone connected)", resp.StatusCode)
	}
	if m := decodeJSON(t, resp); m["error"] != "no phone connected" {
		t.Errorf("body = %v, want error %q", m, "no phone connected")
	}
}

// TestDecideUnpairedKeyMissingDir: with a missing keys directory, decide
// answers unpaired-key instead of panicking.
func TestDecideUnpairedKeyMissingDir(t *testing.T) {
	store := NewStore()
	_, priv := newKey(t)
	s, err := store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	code, _, key := decide(store, newKeyProvider(t.TempDir()+"/missing"), s.ID, "approve", signDecision(priv, "approve", s))
	if code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 (unpaired-key)", code)
	}
	if key != "" {
		t.Errorf("key = %q, want empty on failure", key)
	}
}
