package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

	keys := newKeyProvider(*keysDir)
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
	log.Printf("phone-fprint-auth daemon: local=%s (%d paired key(s))", *socketPath, keys.Count())

	// Phone surface: the -phone-sim-socket listener is test-only: it accepts
	// plain framed streams over a unix socket exactly like a phone link will.
	if *simSocketPath != "" {
		ln, err := servePhoneSimSocket(*simSocketPath, store, keys)
		if err != nil {
			log.Fatal(err)
		}
		defer ln.Close()
		log.Printf("phone-fprint-auth daemon: phone sim socket listening on %s", *simSocketPath)
	}

	// Phone surface: the real link is the BlueZ SPP server (bt.go).
	// Deliberately non-fatal: without Bluetooth the daemon still serves the
	// unix-socket surface and PAM falls back to the password prompt.
	if err := startSppServer(*adapter, store, keys); err != nil {
		log.Printf("bluetooth unavailable: %v", err)
	}

	select {}
}

// servePhoneSimSocket listens on the given unix socket path and hands every
// accepted connection to startPhoneLink. Any stale socket file from a
// previous run is removed first; the socket file is chmodded 0700. The
// returned listener must be closed by the caller to stop accepting.
func servePhoneSimSocket(path string, store *Store, keys *keyProvider) (net.Listener, error) {
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
func newLocalMux(store *Store, keys *keyProvider) http.Handler {
	mux := http.NewServeMux()

	// Go 1.18 ServeMux: "/v1/session" matches only the exact path.
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		handleCreateSession(w, r, store, keys)
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

// phoneLinks tracks every accepted phone link by connID. Link
// registration/unregistration happens in phone_link.go; phoneConnected()
// counts only the registered ones.
var phoneLinks = struct {
	sync.Mutex
	links map[connID]*phoneLink
	next  connID
}{links: make(map[connID]*phoneLink)}

// phoneConnected reports whether at least one registered phone link is
// active: a link whose hello pubkey matched a paired key. Unregistered links
// never count, so they cannot make the PAM module wait on a request no phone
// can approve.
func phoneConnected() bool {
	phoneLinks.Lock()
	defer phoneLinks.Unlock()
	for _, l := range phoneLinks.links {
		if l.registered {
			return true
		}
	}
	return false
}

func handleCreateSession(w http.ResponseWriter, r *http.Request, store *Store, keys *keyProvider) {
	// Fail fast with no paired keys: the PAM module falls back to the
	// password prompt instead of polling a request no phone can approve.
	// Keys are re-read on every call, so phone-approve remove takes effect
	// without a daemon restart.
	if keys.Count() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no paired keys"})
		return
	}
	// Fail fast when no registered phone link is connected.
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
		if errors.Is(err, errStoreFull) {
			audit("session-store-full", "max", strconv.Itoa(maxSessions))
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session store full"})
			return
		}
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
// returns the HTTP-ish status code (reused by the frame handler), the
// session's new status, and the matching key's name: 200 decided + key name,
// 400 bad decision value, 401 bad/absent sig or no matching key, 404 unknown
// id. Deciding an already-decided or expired session is idempotent: a 200
// carries the original outcome (already-decided: status + DecidedBy; expired:
// status=expired) so a phone re-deciding after a reconnect recovers its
// verdict instead of an error.
func decide(store *Store, keys *keyProvider, id, decision, sigB64 string) (code int, status string, key string) {
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
	sig, err := base64.StdEncoding.Strict().DecodeString(sigB64)
	if err != nil {
		audit("decision-failed", "id", id, "reason", "invalid-signature")
		return http.StatusUnauthorized, "", ""
	}
	msg := signedMessage(decision, s.User, s.Service, s.TTY, s.Nonce)
	keyName := ""
	for name, k := range keys.All() {
		if ed25519.Verify(k, msg, sig) {
			keyName = name
			break
		}
	}
	if keyName == "" {
		audit("decision-failed", "id", id, "reason", "unpaired-key")
		return http.StatusUnauthorized, "", ""
	}
	if cur := s.CurrentStatus(); cur != StatusPending {
		if cur == StatusExpired {
			return http.StatusOK, StatusExpired, ""
		}
		return http.StatusOK, cur, s.DecidedBy
	}
	newStatus := StatusDenied
	if decision == "approve" {
		newStatus = StatusApproved
	}
	if ok, found := store.Decide(id, newStatus, keyName); !ok {
		if !found {
			audit("decision-failed", "id", id, "reason", "unknown-session")
			return http.StatusNotFound, "", ""
		}
		// Lost a race to another link: report the winner's outcome.
		if s2, ok2 := store.Get(id); ok2 {
			if cur := s2.CurrentStatus(); cur == StatusExpired {
				return http.StatusOK, StatusExpired, ""
			}
			return http.StatusOK, s2.CurrentStatus(), s2.DecidedBy
		}
	}
	audit("decision", "id", id, "decision", decision, "key", keyName)
	return http.StatusOK, newStatus, keyName
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
