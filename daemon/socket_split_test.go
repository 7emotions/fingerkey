package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
