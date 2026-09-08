package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestPendingWaitParse checks the ?wait= parsing, fallback, and clamping
// rules of pendingWait.
func TestPendingWaitParse(t *testing.T) {
	newReq := func(query string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, "http://x/v1/pending"+query, nil)
		if err != nil {
			t.Fatalf("NewRequest(%q): %v", query, err)
		}
		return r
	}

	for _, tc := range []struct {
		query string
		want  time.Duration
	}{
		{"", 60 * time.Second},                              // default
		{"?wait=5", 5 * time.Second},                        // ordinary value
		{"?wait=120", 120 * time.Second},                    // exactly the cap
		{"?wait=121", 120 * time.Second},                    // clamped down to the cap
		{"?wait=99999999", 120 * time.Second},               // huge input clamped
		{"?wait=-1", 60 * time.Second},                      // negative -> default
		{"?wait=abc", 60 * time.Second},                     // malformed -> default
		{"?wait=99999999999999999999999", 60 * time.Second}, // overflow -> default
	} {
		if got := pendingWait(newReq(tc.query)); got != tc.want {
			t.Errorf("pendingWait(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
}

// TestPendingHugeWaitReturnsPromptly hits the real phone mux with
// ?wait=99999999 and asserts it answers 204 promptly. Without the clamp the
// handler would pin the goroutine for ~3 years, so this test fails via the
// client timeout if the clamp regresses. The production cap (120) is asserted
// in TestPendingWaitParse; here the cap is shortened so the test finishes in
// seconds.
func TestPendingHugeWaitReturnsPromptly(t *testing.T) {
	old := maxPendingWaitSecs
	maxPendingWaitSecs = 1
	t.Cleanup(func() { maxPendingWaitSecs = old })

	store := NewStore()
	phone := httptest.NewServer(newPhoneMux(store, nil))
	defer phone.Close()

	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(phone.URL + "/v1/pending?wait=99999999")
	if err != nil {
		t.Fatalf("pending poll with huge wait: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("huge-wait poll took %v, want prompt (<5s) return", elapsed)
	}
}
