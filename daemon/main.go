package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", ":8766", "listen address")
	baseURL := flag.String("base-url", "http://localhost:8766", "public base URL used in approve links")
	flag.Parse()

	log.Printf("T0 UNSIGNED approve endpoint exposed on LAN — LAB USE ONLY (listening on %s)", *addr)
	if err := http.ListenAndServe(*addr, newHandler(NewStore(), *baseURL)); err != nil {
		log.Fatal(err)
	}
}

// newHandler wires the HTTP surface around the given store.
func newHandler(store *Store, baseURL string) http.Handler {
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
		handleCreateSession(w, r, store, limiter, baseURL)
	})

	// Subtree dispatch: one segment = session id, two = {id}/approve.
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
		if len(parts) == 2 && parts[1] == "approve" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			handleApproveSession(w, r, store, parts[0])
			return
		}
		http.NotFound(w, r)
	})

	return mux
}

func handleCreateSession(w http.ResponseWriter, r *http.Request, store *Store, limiter *rateLimiter, baseURL string) {
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
		"id":          s.ID,
		"nonce":       base64.StdEncoding.EncodeToString(s.Nonce),
		"approve_url": baseURL + "/approve/" + s.ID,
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

func handleApproveSession(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	approved, found := store.Approve(id)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	if !approved {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "session is not pending"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
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
