package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", ":8766", "listen address")
	keysDir := flag.String("keys-dir", "/var/lib/phone-fprint-auth/keys", "directory of <name>.pub Ed25519 public keys (base64)")
	flag.Parse()

	keys := loadPubKeys(*keysDir)
	log.Printf("phone-fprint-auth daemon listening on %s (%d paired key(s))", *addr, len(keys))
	if err := http.ListenAndServe(*addr, newHandler(NewStore(), keys)); err != nil {
		log.Fatal(err)
	}
}

// newHandler wires the HTTP surface around the given store and paired keys.
func newHandler(store *Store, keys map[string]ed25519.PublicKey) http.Handler {
	mux := http.NewServeMux()
	limiter := newRateLimiter(10, time.Minute)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})

	// Go 1.18 ServeMux: "/v1/session" matches only the exact path, so subpaths
	// need their own subtree pattern — two registrations, not one.
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		handleCreateSession(w, r, store, limiter)
	})

	mux.HandleFunc("/v1/pending", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		handlePending(w, r, store)
	})

	// Subtree dispatch: one segment = session id, two = {id}/decision.
	mux.HandleFunc("/v1/session/", func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/v1/session/")
		parts := strings.Split(strings.Trim(suffix, "/"), "/")
		if len(parts) == 1 {
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			handleGetSession(w, r, store, parts[0])
			return
		}
		if len(parts) == 2 && parts[1] == "decision" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			handleDecisionSession(w, r, store, keys, parts[0])
			return
		}
		http.NotFound(w, r)
	})

	return mux
}

func handleCreateSession(w http.ResponseWriter, r *http.Request, store *Store, limiter *rateLimiter) {
	if !limiter.allow(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}
	var req struct {
		User    string `json:"user"`
		Service string `json:"service"`
		TTY     string `json:"tty"`
	}
	// All fields optional; a missing/empty/malformed body falls back to "".
	_ = json.NewDecoder(r.Body).Decode(&req)
	s, err := store.Create(req.User, req.Service, req.TTY)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session creation failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":    s.ID,
		"nonce": base64.StdEncoding.EncodeToString(s.Nonce),
	})
}

func handleGetSession(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	s, ok := store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":      s.ID,
		"status":  s.CurrentStatus(),
		"user":    s.User,
		"service": s.Service,
		"tty":     s.TTY,
	})
}

// handleDecisionSession verifies an Ed25519 signature over the pinned decision
// message against any paired pubkey and, on success, transitions the session.
// The matching key's name is recoverable from the keys map for audit
// attribution. Responses: 200 decided, 400 bad decision value, 401 bad/absent
// sig or no matching key, 404 unknown id, 409 not pending (already decided or
// expired).
func handleDecisionSession(w http.ResponseWriter, r *http.Request, store *Store, keys map[string]ed25519.PublicKey, id string) {
	s, ok := store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Sig      string `json:"sig"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	switch req.Decision {
	case "approve", "deny":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be approve or deny"})
		return
	}
	if s.CurrentStatus() != StatusPending {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "session is not pending"})
		return
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(req.Sig)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}
	msg := signedMessage(req.Decision, s.User, s.Service, s.TTY, s.Nonce)
	for name, key := range keys {
		if ed25519.Verify(key, msg, sig) {
			status := StatusDenied
			if req.Decision == "approve" {
				status = StatusApproved
			}
			if ok, _ := store.Decide(id, status); !ok {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "session is not pending"})
				return
			}
			// name is the paired-key identity that verified this decision;
			// the audit log (todo 2) will attribute the decision to it.
			writeJSON(w, http.StatusOK, map[string]string{"status": s.CurrentStatus(), "key": name})
			return
		}
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature verification failed"})
}

// handlePending is the long-poll endpoint: it holds up to wait seconds and
// returns 200 with the new session as soon as one is created, or 204 when the
// wait elapses. wait is given in seconds (?wait=<sec>), default 60.
func handlePending(w http.ResponseWriter, r *http.Request, store *Store) {
	wait := 60 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			wait = time.Duration(secs) * time.Second
		}
	}
	s := store.WaitPending(wait)
	if s == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":      s.ID,
		"nonce":   base64.StdEncoding.EncodeToString(s.Nonce),
		"user":    s.User,
		"service": s.Service,
		"tty":     s.TTY,
	})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP returns the remote IP of the request (RemoteAddr without port).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimiter is a fixed-window in-memory per-key counter.
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*rateEntry
}

type rateEntry struct {
	start time.Time
	count int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]*rateEntry),
	}
}

// allow reports whether key is under the limit for the current window.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e, ok := rl.entries[key]
	if !ok || now.Sub(e.start) >= rl.window {
		rl.entries[key] = &rateEntry{start: now, count: 1}
		return true
	}
	e.count++
	return e.count <= rl.limit
}
