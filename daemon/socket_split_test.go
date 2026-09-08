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

// TestSocketSplit asserts the split between the root-only local surface
// (unix socket) and the phone surface (TCP): each mux 404s the other's
// endpoints and serves only its own.
func TestSocketSplit(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	store := NewStore()
	keys := map[string]ed25519.PublicKey{"alice": pub}

	local := httptest.NewServer(newLocalMux(store))
	defer local.Close()
	phone := httptest.NewServer(newPhoneMux(store, keys))
	defer phone.Close()

	// The local mux must not serve phone endpoints.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/pending"},
		{http.MethodPost, "/v1/session/deadbeef/decision"},
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

	// The phone mux must not serve local endpoints.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/session"},
		{http.MethodGet, "/v1/session/deadbeef"},
	} {
		req, _ := http.NewRequest(tc.method, phone.URL+tc.path, strings.NewReader(`{}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("phone mux %s %s = %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}

	// POST /v1/session on the phone mux must be a real 404 — no 301 redirect
	// to the subtree pattern and no session creation.
	t.Run("phone POST /v1/session is a real 404", func(t *testing.T) {
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		req, _ := http.NewRequest(http.MethodPost, phone.URL+"/v1/session", strings.NewReader(`{}`))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST /v1/session: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Errorf("unexpected Location header %q, want a real 404 with no redirect", loc)
		}

		// The 404 handler must not have created a session: a short
		// WaitPending would return it if it had.
		created := make(chan *Session, 1)
		go func() { created <- store.WaitPending(200 * time.Millisecond) }()
		select {
		case s := <-created:
			if s != nil {
				t.Errorf("POST /v1/session created session %q, want none", s.ID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("WaitPending did not return")
		}
	})

	// Each mux serves its own endpoints: a valid create on local, healthz on phone.
	resp := postJSON(t, local.URL+"/v1/session", `{"user":"alice","service":"sudo"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("local POST /v1/session = %d, want 200", resp.StatusCode)
	}

	hresp, err := http.Get(phone.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		t.Fatalf("phone GET /healthz = %d, want 200", hresp.StatusCode)
	}
}
