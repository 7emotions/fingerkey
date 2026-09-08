package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
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

// testEnv bundles both surfaces of the split: the root-only local mux (unix
// socket, session creation + status) and the phone mux (TCP, pending +
// decision + healthz), both served over ONE shared Store so a session created
// on local is visible to the phone's decision endpoint and the local status
// poll.
type testEnv struct {
	local *httptest.Server
	phone *httptest.Server
	store *Store
	priv  ed25519.PrivateKey
}

// newTestEnv builds both httptest servers over a shared store + key map.
func newTestEnv(t *testing.T, keys map[string]ed25519.PublicKey, priv ed25519.PrivateKey) *testEnv {
	t.Helper()
	store := NewStore()
	local := httptest.NewServer(newLocalMux(store, keys))
	phone := httptest.NewServer(newPhoneMux(store, keys))
	t.Cleanup(local.Close)
	t.Cleanup(phone.Close)
	return &testEnv{local: local, phone: phone, store: store, priv: priv}
}

// newTestServer builds a split harness with one freshly generated paired key.
func newTestServer(t *testing.T) *testEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return newTestEnv(t, map[string]ed25519.PublicKey{"alice": pub}, priv)
}

// newTestServerNoKeys builds a split harness with NO paired keys (empty keys
// dir case): POST /v1/session on the local mux is 503, and every /decision is
// 401.
func newTestServerNoKeys(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnv(t, map[string]ed25519.PublicKey{}, nil)
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

func TestHealthz(t *testing.T) {
	env := newTestServer(t)
	resp, err := http.Get(env.phone.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}

func TestHandlerCreateSession(t *testing.T) {
	env := newTestServer(t)
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

func decisionBody(priv ed25519.PrivateKey, action string, s *Session) string {
	return `{"decision":"` + action + `","sig":"` + signDecision(priv, action, s) + `"}`
}

func TestHandlerDecisionApprove(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", decisionBody(env.priv, "approve", s))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["status"] != StatusApproved {
		t.Errorf("body = %v, want status %q", m, StatusApproved)
	}
}

func TestHandlerDecisionDeny(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", decisionBody(env.priv, "deny", s))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["status"] != StatusDenied {
		t.Errorf("body = %v, want status %q", m, StatusDenied)
	}
	if s.Status != StatusDenied {
		t.Errorf("session status = %q, want %q", s.Status, StatusDenied)
	}
}

// Replay: once decided, a second /decision — even with the valid signature —
// is a conflict.
func TestHandlerDecisionTwice(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", decisionBody(env.priv, "approve", s))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first decision status = %d, want 200", resp.StatusCode)
	}
	resp = postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", decisionBody(env.priv, "approve", s))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second decision status = %d, want 409", resp.StatusCode)
	}
}

func TestHandlerDecisionUnknown(t *testing.T) {
	env := newTestServer(t)
	s := &Session{Nonce: make([]byte, 32), User: "x", Service: "y", TTY: ""}
	resp := postJSON(t, env.phone.URL+"/v1/session/doesnotexist/decision", decisionBody(env.priv, "approve", s))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerDecisionWrongKey(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, otherPriv := newKey(t) // unpaired key
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", decisionBody(otherPriv, "approve", s))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if s.Status != StatusPending {
		t.Fatalf("session status = %q, want %q (unchanged)", s.Status, StatusPending)
	}
}

func TestHandlerDecisionNoKeys(t *testing.T) {
	env := newTestServerNoKeys(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, priv := newKey(t) // signature from a valid key, but nothing is paired
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", decisionBody(priv, "approve", s))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no paired keys)", resp.StatusCode)
	}
}

func TestHandlerDecisionMissingSig(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", `{"decision":"approve"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlerDecisionGarbageSig(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", `{"decision":"approve","sig":"!!!not-base64!!!"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlerDecisionBadDecision(t *testing.T) {
	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", `{"decision":"maybe","sig":""}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerDecisionExpired(t *testing.T) {
	old := sessionTTL
	sessionTTL = 20 * time.Millisecond
	defer func() { sessionTTL = old }()

	env := newTestServer(t)
	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	resp := postJSON(t, env.phone.URL+"/v1/session/"+s.ID+"/decision", decisionBody(env.priv, "approve", s))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (expired session cannot be decided)", resp.StatusCode)
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

// ---- /v1/pending long-poll tests ----

func TestHandlerPendingReturnsNewSession(t *testing.T) {
	env := newTestServer(t)

	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := http.Get(env.phone.URL + "/v1/pending?wait=5")
		ch <- result{resp, err}
	}()

	// Give the poller a moment to register its wait.
	time.Sleep(50 * time.Millisecond)

	s, err := env.store.Create("alice", "sudo", "/dev/pts/0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("pending poll: %v", res.err)
		}
		defer res.resp.Body.Close()
		if res.resp.StatusCode != http.StatusOK {
			t.Fatalf("pending poll status = %d, want 200", res.resp.StatusCode)
		}
		m := decodeJSON(t, res.resp)
		if m["id"] != s.ID || m["user"] != "alice" || m["service"] != "sudo" || m["tty"] != "/dev/pts/0" {
			t.Errorf("pending body = %v, want the new session", m)
		}
		nonce, err := base64.StdEncoding.DecodeString(m["nonce"].(string))
		if err != nil || len(nonce) != 32 {
			t.Errorf("pending nonce is not 32 bytes of standard base64: %v", m["nonce"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poller did not return after a session was created")
	}
}

// Multiple concurrent pollers must EACH receive the new session (broadcast,
// not consume).
func TestHandlerPendingMultiplePollers(t *testing.T) {
	env := newTestServer(t)

	const pollers = 3
	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, pollers)
	for i := 0; i < pollers; i++ {
		go func() {
			resp, err := http.Get(env.phone.URL + "/v1/pending?wait=5")
			ch <- result{resp, err}
		}()
	}
	time.Sleep(50 * time.Millisecond)

	s, err := env.store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for i := 0; i < pollers; i++ {
		select {
		case res := <-ch:
			if res.err != nil {
				t.Fatalf("poller %d: %v", i, res.err)
			}
			defer res.resp.Body.Close()
			if res.resp.StatusCode != http.StatusOK {
				t.Fatalf("poller %d status = %d, want 200", i, res.resp.StatusCode)
			}
			m := decodeJSON(t, res.resp)
			if m["id"] != s.ID {
				t.Errorf("poller %d got id %v, want %q", i, m["id"], s.ID)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("poller %d did not return", i)
		}
	}
}

func TestHandlerPendingTimeout(t *testing.T) {
	env := newTestServer(t)
	resp, err := http.Get(env.phone.URL + "/v1/pending?wait=0")
	if err != nil {
		t.Fatalf("GET /v1/pending: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (no new session)", resp.StatusCode)
	}
}
