package main

import (
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

func newTestServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	st := NewStore()
	ts := httptest.NewServer(newHandler(st, "http://localhost:8766"))
	t.Cleanup(ts.Close)
	return ts, st
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
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
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
	ts, _ := newTestServer(t)
	resp := postJSON(t, ts.URL+"/v1/session", `{"user":"alice","service":"sudo","tty":"/dev/pts/0"}`)
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
	want := "http://localhost:8766/approve/" + id
	if m["approve_url"] != want {
		t.Errorf("approve_url = %v, want %q", m["approve_url"], want)
	}
}

func TestHandlerCreateSessionDefaults(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := postJSON(t, ts.URL+"/v1/session", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["id"] == nil || m["nonce"] == nil || m["approve_url"] == nil {
		t.Errorf("missing fields in response: %v", m)
	}
}

func TestHandlerGetSession(t *testing.T) {
	ts, st := newTestServer(t)
	s, err := st.Create("alice", "sudo", "/dev/pts/0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp, err := http.Get(ts.URL + "/v1/session/" + s.ID)
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
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/v1/session/doesnotexist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerApprove(t *testing.T) {
	ts, st := newTestServer(t)
	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, ts.URL+"/v1/session/"+s.ID+"/approve", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["status"] != StatusApproved {
		t.Errorf("body = %v, want status %q", m, StatusApproved)
	}
}

func TestHandlerApproveTwice(t *testing.T) {
	ts, st := newTestServer(t)
	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	postJSON(t, ts.URL+"/v1/session/"+s.ID+"/approve", "")
	resp := postJSON(t, ts.URL+"/v1/session/"+s.ID+"/approve", "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second approve status = %d, want 409", resp.StatusCode)
	}
}

func TestHandlerApproveUnknown(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := postJSON(t, ts.URL+"/v1/session/doesnotexist/approve", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerSessionExpiredStatus(t *testing.T) {
	old := sessionTTL
	sessionTTL = 20 * time.Millisecond
	defer func() { sessionTTL = old }()

	ts, st := newTestServer(t)
	s, err := st.Create("alice", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	resp, err := http.Get(ts.URL + "/v1/session/" + s.ID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	m := decodeJSON(t, resp)
	if m["status"] != StatusExpired {
		t.Errorf("status = %v, want %q", m["status"], StatusExpired)
	}
}

func TestHandlerRateLimit(t *testing.T) {
	ts, _ := newTestServer(t)
	last := 0
	for i := 0; i < 15; i++ {
		resp := postJSON(t, ts.URL+"/v1/session", `{}`)
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status after limit exceeded = %d, want 429", last)
	}
}
