package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func main() {
	adapter := flag.String("adapter", "hci0", "Bluetooth HCI adapter for the SPP phone link")
	socketPath := flag.String("socket", "/run/phone-fprint-auth/daemon.sock", "unix socket path for the root-only local surface")
	keysDir := flag.String("keys-dir", "/var/lib/phone-fprint-auth/keys", "directory of <name>.pub Ed25519 public keys (base64)")
	simSocketPath := flag.String("phone-sim-socket", "", "unix socket path for a test phone link (empty = disabled)")
	flag.Parse()

	log.Printf("phone-fprint-auth daemon: adapter=%s", *adapter)

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
	log.Printf("phone-fprint-auth daemon: local=%s (%d paired key(s))", *socketPath, len(keys))

	// Phone surface: the real link is the BlueZ SPP server (see bt.go). The
	// -phone-sim-socket listener is test-only: it accepts plain framed streams
	// over a unix socket exactly like the SPP RFCOMM socket will.
	if *simSocketPath != "" {
		ln, err := servePhoneSimSocket(*simSocketPath, store, keys)
		if err != nil {
			log.Fatal(err)
		}
		defer ln.Close()
		log.Printf("phone-fprint-auth daemon: phone sim socket listening on %s", *simSocketPath)
	}

	select {}
}

// servePhoneSimSocket listens on the given unix socket path and hands every
// accepted connection to startPhoneLink. Any stale socket file from a
// previous run is removed first; the socket file is chmodded 0700. The
// returned listener must be closed by the caller to stop accepting.
func servePhoneSimSocket(path string, store *Store, keys map[string]ed25519.PublicKey) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0700); err != nil {
		ln.Close()
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			startPhoneLink(conn, store, keys)
		}
	}()
	return ln, nil
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

// phoneLinks tracks the number of active phone links (SPP-connected phones).
// Link registration/unregistration happens in phone_link.go.
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

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
