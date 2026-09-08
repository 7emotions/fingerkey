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
	"sync"
	"time"
)

// maxPendingWaitSecs caps the ?wait= long-poll duration: an unauthenticated
// LAN peer must not be able to pin a goroutine + timer for arbitrary time,
// and huge inputs must not overflow the time.Duration conversion. It is a
// package var (like sessionTTL) so tests can shorten it.
var maxPendingWaitSecs = 120

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
		if err := http.Serve(localLn, newLocalMux(store, keys)); err != nil {
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
// keys are the paired Ed25519 pubkeys: with none paired, session creation
// fails fast with 503 so the PAM module falls back to the password prompt
// instead of polling a request no phone can approve.
func newLocalMux(store *Store, keys map[string]ed25519.PublicKey) http.Handler {
	mux := http.NewServeMux()

	// Go 1.18 ServeMux: "/v1/session" matches only the exact path.
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if len(keys) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no paired keys"})
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

	// Session creation is root-only and lives on the local unix-socket mux.
	// Register the exact path here so POST /v1/session on the phone surface
	// gets a real 404 instead of a 301 redirect to the subtree below.
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
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

// phoneLinks tracks the number of active phone links (SPP-connected phones).
// Link registration/unregistration is wired by later todos; today only
// phoneConnected reads the count.
var phoneLinks = struct {
	sync.Mutex
	active int
}{}

// phoneConnected reports whether at least one phone link is active.
func phoneConnected() bool {
	phoneLinks.Lock()
	defer phoneLinks.Unlock()
	return phoneLinks.active > 0
}

func handleCreateSession(w http.ResponseWriter, r *http.Request, store *Store) {
	// Fail fast when no phone is connected: the PAM module falls back to the
	// password prompt instead of polling a request no phone can approve.
	// (The no-paired-keys 503 is checked earlier, in newLocalMux.)
	if !phoneConnected() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no phone connected"})
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

// decide verifies an Ed25519 signature over the pinned decision message
// against any paired pubkey and, on success, transitions the session. It
// returns the HTTP-ish status code (reused by the SPP frame handler), the
// session's new status, and the matching key's name: 200 decided + key name,
// 400 bad decision value, 401 bad/absent sig or no matching key, 404 unknown
// id, 409 not pending (already decided or expired).
func decide(store *Store, keys map[string]ed25519.PublicKey, id, decision, sigB64 string) (code int, status string, key string) {
	s, ok := store.Get(id)
	if !ok {
		audit("decision-failed", "id", id, "reason", "unknown-session")
		return http.StatusNotFound, "", ""
	}
	switch decision {
	case "approve", "deny":
	default:
		audit("decision-failed", "id", id, "reason", "bad-decision")
		return http.StatusBadRequest, "", ""
	}
	if s.CurrentStatus() != StatusPending {
		audit("decision-failed", "id", id, "reason", "not-pending")
		return http.StatusConflict, "", ""
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(sigB64)
	if err != nil {
		audit("decision-failed", "id", id, "reason", "invalid-signature")
		return http.StatusUnauthorized, "", ""
	}
	msg := signedMessage(decision, s.User, s.Service, s.TTY, s.Nonce)
	for name, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			newStatus := StatusDenied
			if decision == "approve" {
				newStatus = StatusApproved
			}
			if ok, _ := store.Decide(id, newStatus); !ok {
				audit("decision-failed", "id", id, "reason", "not-pending")
				return http.StatusConflict, "", ""
			}
			audit("decision", "id", id, "decision", decision, "key", name)
			return http.StatusOK, s.CurrentStatus(), name
		}
	}
	audit("decision-failed", "id", id, "reason", "unpaired-key")
	return http.StatusUnauthorized, "", ""
}

// handleDecisionSession decodes the signed decision request and delegates
// verification and transition to decide. Responses: 200 decided, 400 bad
// decision value, 401 bad/absent sig or no matching key, 404 unknown id,
// 409 not pending (already decided or expired).
func handleDecisionSession(w http.ResponseWriter, r *http.Request, store *Store, keys map[string]ed25519.PublicKey, id string) {
	var req struct {
		Decision string `json:"decision"`
		Sig      string `json:"sig"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	code, status, key := decide(store, keys, id, req.Decision, req.Sig)
	switch code {
	case http.StatusOK:
		writeJSON(w, code, map[string]string{"status": status, "key": key})
	case http.StatusBadRequest:
		writeJSON(w, code, map[string]string{"error": "decision must be approve or deny"})
	case http.StatusUnauthorized:
		writeJSON(w, code, map[string]string{"error": "invalid signature"})
	case http.StatusNotFound:
		writeJSON(w, code, map[string]string{"error": "unknown session"})
	case http.StatusConflict:
		writeJSON(w, code, map[string]string{"error": "session is not pending"})
	default:
		writeJSON(w, code, map[string]string{"error": "decision failed"})
	}
}

// handlePending is the long-poll endpoint: it holds up to wait seconds and
// returns 200 with the new session as soon as one is created, or 204 when the
// wait elapses. wait is given in seconds (?wait=<sec>), default 60, clamped to
// maxPendingWaitSecs.
func handlePending(w http.ResponseWriter, r *http.Request, store *Store) {
	s := store.WaitPending(pendingWait(r))
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

// pendingWait parses ?wait=<sec> (default 60) and clamps it to
// maxPendingWaitSecs. Malformed, negative, or out-of-range values fall back
// to the default; huge values are clamped instead of pinning a goroutine
// for an arbitrary duration.
func pendingWait(r *http.Request) time.Duration {
	wait := 60 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			if secs > maxPendingWaitSecs {
				secs = maxPendingWaitSecs
			}
			wait = time.Duration(secs) * time.Second
		}
	}
	return wait
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
