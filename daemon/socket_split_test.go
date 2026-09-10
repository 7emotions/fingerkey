package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// assertNoCreate fails if a session is delivered to a fresh subscriber within
// 200ms — the Subscribe-based stand-in for the deleted WaitPending: it proves
// a request did NOT create a session.
func assertNoCreate(t *testing.T, store *Store) {
	t.Helper()
	ch, unsub := store.Subscribe()
	defer unsub()
	select {
	case s := <-ch:
		t.Errorf("a session was created (%q), want none", s.ID)
	case <-time.After(200 * time.Millisecond):
		// expected: nothing was created
	}
}

// TestSocketSplit asserts the local mux's surface after the phone mux was
// removed: the former phone endpoints (long-poll, decision) are 404 and the
// root-only session endpoints still serve.
func TestSocketSplit(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	linkPhone(t)
	store := NewStore()
	keys := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub})

	local := httptest.NewServer(newLocalMux(store, keys, nil))
	defer local.Close()

	// The local mux must not serve the removed phone endpoints.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/pending"},
		{http.MethodPost, "/v1/session/deadbeef/decision"},
		{http.MethodGet, "/healthz"},
	} {
		req, _ := http.NewRequest(tc.method, local.URL+tc.path, strings.NewReader(`{}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("local mux %s %s = %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}

	// POST /v1/session/.../decision must be a real 404 — no session creation.
	req, _ := http.NewRequest(http.MethodPost, local.URL+"/v1/session/deadbeef/decision", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST decision: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	assertNoCreate(t, store)

	// The local mux still serves its own endpoints: a valid create and a status poll.
	resp = postJSON(t, local.URL+"/v1/session", `{"user":"alice","service":"sudo"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("local POST /v1/session = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatal("create returned no session id")
	}
	gresp, err := http.Get(local.URL + "/v1/session/" + id)
	if err != nil {
		t.Fatalf("GET session: %v", err)
	}
	defer gresp.Body.Close()
	if gresp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/session/{id} = %d, want 200", gresp.StatusCode)
	}
}

// TestLocalSessionCreateNoKeys asserts the fail-fast path on the local
// surface: with ZERO paired keys, POST /v1/session must return 503 and must
// NOT create a session, so the PAM module falls back to the password prompt
// immediately instead of polling 60s for a phone that can never approve.
// With at least one paired key, the normal path must still create a session.
func TestLocalSessionCreateNoKeys(t *testing.T) {
	store := NewStore()

	local := httptest.NewServer(newLocalMux(store, newTestKeyProvider(t, nil), nil))
	defer local.Close()

	ch, unsub := store.Subscribe()
	defer unsub()
	resp := postJSON(t, local.URL+"/v1/session", `{"user":"alice","service":"sudo"}`)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("empty keys: status = %d, want 503", resp.StatusCode)
	}
	if m := decodeJSON(t, resp); m["error"] != "no paired keys" {
		t.Errorf("empty keys: body = %v, want error %q", m, "no paired keys")
	}
	// The 503 must not have created a session: the subscriber registered
	// above must receive nothing.
	select {
	case s := <-ch:
		t.Errorf("empty keys: POST /v1/session created session %q, want none", s.ID)
	case <-time.After(200 * time.Millisecond):
		// expected: nothing was created
	}

	// Control: with a paired key and a connected phone link, the normal path
	// still creates a session.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	linkPhone(t)
	withKey := httptest.NewServer(newLocalMux(store, newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pub}), nil))
	defer withKey.Close()
	resp = postJSON(t, withKey.URL+"/v1/session", `{"user":"alice","service":"sudo"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with keys: status = %d, want 200", resp.StatusCode)
	}
}
