package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- store-level tests ----

func TestCreateSession(t *testing.T) {
	st := NewStore()
	s, err := st.Create("alice", "sudo", "/dev/pts/0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == "" {
		t.Error("id must not be empty")
	}
	if len(s.ID) != 32 {
		t.Errorf("id length = %d, want 32 hex chars (128-bit)", len(s.ID))
	}
	if _, err := hex.DecodeString(s.ID); err != nil {
		t.Errorf("id is not valid hex: %v", err)
	}
	if len(s.Nonce) != 32 {
		t.Errorf("nonce length = %d, want 32 bytes", len(s.Nonce))
	}
	if s.Status != StatusPending {
		t.Errorf("status = %q, want %q", s.Status, StatusPending)
	}
	if s.User != "alice" || s.Service != "sudo" || s.TTY != "/dev/pts/0" {
		t.Errorf("fields not stored: user=%q service=%q tty=%q", s.User, s.Service, s.TTY)
	}
	if got := s.ExpiresAt.Sub(s.CreatedAt); got != sessionTTL {
		t.Errorf("TTL = %v, want %v", got, sessionTTL)
	}
}

func TestSessionExpiry(t *testing.T) {
	old := sessionTTL
	sessionTTL = 20 * time.Millisecond
	defer func() { sessionTTL = old }()

	st := NewStore()
	s, err := st.Create("alice", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := s.CurrentStatus(); got != StatusExpired {
		t.Fatalf("status = %q, want %q", got, StatusExpired)
	}
}

func TestApprovePendingToApproved(t *testing.T) {
	st := NewStore()
	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	approved, found := st.Approve(s.ID)
	if !found {
		t.Fatal("Approve: session not found")
	}
	if !approved {
		t.Fatal("first approve should succeed")
	}
	if got := s.CurrentStatus(); got != StatusApproved {
		t.Fatalf("status = %q, want %q", got, StatusApproved)
	}
}

func TestApproveOnceOnly(t *testing.T) {
	st := NewStore()
	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if approved, _ := st.Approve(s.ID); !approved {
		t.Fatal("first approve should succeed")
	}
	approved, found := st.Approve(s.ID)
	if !found {
		t.Fatal("second approve must still find the session")
	}
	if approved {
		t.Fatal("second approve must not succeed (once-only)")
	}
	if s.Status != StatusApproved {
		t.Fatalf("status = %q, want %q (unchanged)", s.Status, StatusApproved)
	}
}

func TestDecideDeny(t *testing.T) {
	st := NewStore()
	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ok, found := st.Decide(s.ID, StatusDenied)
	if !found || !ok {
		t.Fatal("Decide(deny) should succeed on a pending session")
	}
	if s.Status != StatusDenied {
		t.Fatalf("status = %q, want %q", s.Status, StatusDenied)
	}
	// deny is also once-only
	if ok, found := st.Decide(s.ID, StatusDenied); found && ok {
		t.Fatal("second Decide must not succeed (once-only)")
	}
}

func TestUnknownSession(t *testing.T) {
	st := NewStore()
	if _, ok := st.Get("deadbeef"); ok {
		t.Fatal("Get found unknown id")
	}
	if _, found := st.Approve("deadbeef"); found {
		t.Fatal("Approve found unknown id")
	}
}

// ---- HTTP handler tests ----

// testEnv bundles the root-only local mux (unix socket, session creation +
// status) over a Store.
type testEnv struct {
	local *httptest.Server
	store *Store
}

// newTestEnv builds one httptest server over a fresh store + key map.
func newTestEnv(t *testing.T, keys map[string]ed25519.PublicKey) *testEnv {
	t.Helper()
	store := NewStore()
	local := httptest.NewServer(newLocalMux(store, keys))
	t.Cleanup(local.Close)
	return &testEnv{local: local, store: store}
}

// newTestServer builds a harness with one freshly generated paired key.
func newTestServer(t *testing.T) *testEnv {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return newTestEnv(t, map[string]ed25519.PublicKey{"alice": pub})
}

// linkPhone marks one phone link as connected for the duration of the test.
// Session creation over the local mux fails fast with 503 when no link is
// active, so tests exercising the normal create path need this.
func linkPhone(t *testing.T) {
	t.Helper()
	phoneLinks.Lock()
	phoneLinks.active++
	phoneLinks.Unlock()
	t.Cleanup(func() {
		phoneLinks.Lock()
		phoneLinks.active--
		phoneLinks.Unlock()
	})
}

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return m
}

func TestHandlerCreateSession(t *testing.T) {
	env := newTestServer(t)
	linkPhone(t)
	resp := postJSON(t, env.local.URL+"/v1/session", `{"user":"alice","service":"sudo","tty":"/dev/pts/0"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatal("id missing or empty")
	}
	nonceB64, _ := m["nonce"].(string)
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		t.Fatalf("nonce is not valid standard base64: %v", err)
	}
	if len(nonce) != 32 {
		t.Errorf("nonce decodes to %d bytes, want 32", len(nonce))
	}
	if _, has := m["approve_url"]; has {
		t.Errorf("approve_url must be gone from the signed-protocol response: %v", m)
	}
}

func TestHandlerCreateSessionDefaults(t *testing.T) {
	env := newTestServer(t)
	linkPhone(t)
	resp := postJSON(t, env.local.URL+"/v1/session", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["id"] == nil || m["nonce"] == nil {
		t.Errorf("missing fields in response: %v", m)
	}
}

func TestHandlerGetSession(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "/dev/pts/0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp, err := http.Get(env.local.URL + "/v1/session/" + s.ID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	m := decodeJSON(t, resp)
	if m["id"] != s.ID || m["status"] != StatusPending || m["user"] != "alice" ||
		m["service"] != "sudo" || m["tty"] != "/dev/pts/0" {
		t.Errorf("unexpected body: %v", m)
	}
}

func TestHandlerGetUnknownSession(t *testing.T) {
	env := newTestServer(t)
	resp, err := http.Get(env.local.URL + "/v1/session/doesnotexist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// The T0 unsigned approve endpoint must be GONE.
func TestHandlerNoUnsignedApprove(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, env.local.URL+"/v1/session/"+s.ID+"/approve", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /v1/session/{id}/approve status = %d, want 404 (endpoint removed)", resp.StatusCode)
	}
}

func TestHandlerSessionExpiredStatus(t *testing.T) {
	old := sessionTTL
	sessionTTL = 20 * time.Millisecond
	defer func() { sessionTTL = old }()

	env := newTestServer(t)
	s, err := env.store.Create("alice", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	resp, err := http.Get(env.local.URL + "/v1/session/" + s.ID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	m := decodeJSON(t, resp)
	if m["status"] != StatusExpired {
		t.Errorf("status = %v, want %q", m["status"], StatusExpired)
	}
}
