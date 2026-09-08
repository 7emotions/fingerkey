package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", ":8766", "listen address")
	socketPath := flag.String("socket", "/run/phone-fprint-auth/daemon.sock", "unix socket path for the root-only local surface")
	keysDir := flag.String("keys-dir", "/var/lib/phone-fprint-auth/keys", "directory of <name>.pub Ed25519 public keys (base64)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (PEM) for the phone (TCP) listener")
	tlsKey := flag.String("tls-key", "", "TLS private key file (PEM) for the phone (TCP) listener")
	flag.Parse()

	// HTTPS-only phone surface: the TCP listener MUST NOT start without a
	// valid certificate + key. No plain-HTTP fallback.
	if *tlsCert == "" || *tlsKey == "" {
		log.Fatal("both -tls-cert and -tls-key are required (HTTPS-only)")
	}
	tlsCfg, err := loadTLSConfig(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatal(err)
	}

	keys := loadPubKeys(*keysDir)
	store := NewStore()

	// Local surface: root-only session creation and status polling over a 0700
	// unix socket. systemd's RuntimeDirectory normally owns the parent dir;
	// MkdirAll is best-effort for running outside the unit. Remove any stale
	// socket left by a previous run, then chmod the socket file itself to 0700
	// so only root (DAC override) can connect.
	_ = os.MkdirAll(filepath.Dir(*socketPath), 0700)
	_ = os.Remove(*socketPath)
	localLn, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*socketPath, 0700); err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := http.Serve(localLn, newLocalMux(store)); err != nil {
			log.Fatal(err)
		}
	}()

	// Phone surface: LAN long-poll, signed decision, healthz. HTTPS-only
	// (TLS >= 1.2) via tls.NewListener; plain HTTP is refused at startup.
	phoneLn, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("phone-fprint-auth daemon: local=%s phone=%s (%d paired key(s))", *socketPath, *addr, len(keys))
	go func() {
		if err := http.Serve(tls.NewListener(phoneLn, tlsCfg), newPhoneMux(store, keys)); err != nil {
			log.Fatal(err)
		}
	}()

	select {}
}

// loadTLSConfig loads the PEM certificate + key pair and returns a server
// tls.Config enforcing TLS >= 1.2. CipherSuites is left unset so Go's default
// (safe, policy-tracked) cipher list applies.
func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// newLocalMux wires the root-only local surface (unix socket): session
// creation (POST /v1/session) and status polling (GET /v1/session/{id}) only.
func newLocalMux(store *Store) http.Handler {
	mux := http.NewServeMux()

	// Go 1.18 ServeMux: "/v1/session" matches only the exact path.
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		handleCreateSession(w, r, store)
	})

	// Subtree dispatch: one segment = session id (status).
	mux.HandleFunc("/v1/session/", func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/v1/session/")
		parts := strings.Split(strings.Trim(suffix, "/"), "/")
		if len(parts) == 1 && r.Method == http.MethodGet {
			handleGetSession(w, r, store, parts[0])
			return
		}
		http.NotFound(w, r)
	})

	return mux
}

// newPhoneMux wires the LAN phone surface (TCP): pending long-poll
// (GET /v1/pending), signed decision (POST /v1/session/{id}/decision), and
// healthz only.
func newPhoneMux(store *Store, keys map[string]ed25519.PublicKey) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "ok")
	})

	mux.HandleFunc("/v1/pending", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		handlePending(w, r, store)
	})

	// Subtree dispatch: two segments = {id}/decision.
	mux.HandleFunc("/v1/session/", func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/v1/session/")
		parts := strings.Split(strings.Trim(suffix, "/"), "/")
		if len(parts) == 2 && parts[1] == "decision" && r.Method == http.MethodPost {
			handleDecisionSession(w, r, store, keys, parts[0])
			return
		}
		http.NotFound(w, r)
	})

	return mux
}

func handleCreateSession(w http.ResponseWriter, r *http.Request, store *Store) {
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
	audit("session-created", "id", s.ID, "user", s.User, "service", s.Service, "tty", s.TTY)
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
		audit("decision-failed", "id", id, "reason", "unknown-session")
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
		audit("decision-failed", "id", id, "reason", "bad-decision")
		return
	}
	if s.CurrentStatus() != StatusPending {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "session is not pending"})
		audit("decision-failed", "id", id, "reason", "not-pending")
		return
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(req.Sig)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		audit("decision-failed", "id", id, "reason", "invalid-signature")
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
				audit("decision-failed", "id", id, "reason", "not-pending")
				return
			}
			// name is the paired-key identity that verified this decision and is
			// logged as key= for audit attribution.
			audit("decision", "id", id, "decision", req.Decision, "key", name)
			writeJSON(w, http.StatusOK, map[string]string{"status": s.CurrentStatus(), "key": name})
			return
		}
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature verification failed"})
	audit("decision-failed", "id", id, "reason", "unpaired-key")
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
