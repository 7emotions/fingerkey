package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// pairTTL is the lifetime of an issued pairing token. It is a package var so
// tests can shorten it.
var pairTTL = 60 * time.Second

var (
	errPairNotReady = errors.New("tls listener not ready")
	errTokenUnknown = errors.New("unknown pairing token")
	errTokenExpired = errors.New("expired pairing token")
)

// pairingEntry is one outstanding pairing token: the name the phone will be
// registered under and the moment the token stops working.
type pairingEntry struct {
	Name    string
	Expires time.Time
}

// pairManager owns the pairing window: it mints one-time tokens on
// POST /v1/pair and consumes them atomically when a phone hello carries one.
// The token's name is the only identity the pairing flow trusts — never the
// hello's name field, which is display-only.
type pairManager struct {
	mu      sync.Mutex
	tokens  map[string]pairingEntry
	keysDir string

	// Transport identity for the pair response, set once the TLS listener is
	// up (setTransport). issue() refuses to mint tokens before then so no
	// phone can be pointed at a listener that does not exist.
	fp    string
	host  string
	port  int
	ready bool
}

// newPairManager returns a pairManager writing keys into keysDir.
func newPairManager(keysDir string) *pairManager {
	return &pairManager{tokens: make(map[string]pairingEntry), keysDir: keysDir}
}

// setTransport records the TLS fingerprint and the numeric-IP host:port the
// pair response advertises. Called once the TLS listener is bound.
func (pm *pairManager) setTransport(fp, host string, port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.fp, pm.host, pm.port, pm.ready = fp, host, port, true
}

// issue mints a fresh one-time token for name, purging expired tokens first.
// It refuses names that cannot become a safe <name>.pub filename and refuses
// to mint before the TLS listener is up.
func (pm *pairManager) issue(name string) (string, error) {
	if !validPairName(name) {
		return "", errors.New("invalid pairing name")
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if !pm.ready {
		return "", errPairNotReady
	}
	now := time.Now()
	for k, e := range pm.tokens {
		if now.After(e.Expires) {
			delete(pm.tokens, k)
		}
	}
	token, err := randomHex(16)
	if err != nil {
		return "", err
	}
	pm.tokens[token] = pairingEntry{Name: name, Expires: now.Add(pairTTL)}
	return token, nil
}

// validPairName reports whether name can safely become keysDir/<name>.pub.
func validPairName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, `/\`)
}

// consume atomically consumes token: the entry is deleted under the mutex
// BEFORE validation, so a second use of the same token can never win even if
// the two hellos race. On success the phone's pubkey is written to
// <name>.pub (overwriting any existing file, reported via replaced) and
// pair-registered is audited. Unknown/expired tokens and write failures audit
// pair-failed and never touch the keys dir.
func (pm *pairManager) consume(token string, pub ed25519.PublicKey) (name string, replaced bool, err error) {
	pm.mu.Lock()
	entry, ok := pm.tokens[token]
	delete(pm.tokens, token) // atomic consume: the token is gone either way
	pm.mu.Unlock()
	if !ok {
		audit("pair-failed", "reason", "unknown-token")
		return "", false, errTokenUnknown
	}
	if time.Now().After(entry.Expires) {
		audit("pair-failed", "reason", "expired-token")
		return "", false, errTokenExpired
	}

	path := filepath.Join(pm.keysDir, entry.Name+".pub")
	if _, statErr := os.Stat(path); statErr == nil {
		replaced = true
	}
	data := base64.StdEncoding.EncodeToString(pub) + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		audit("pair-failed", "reason", "key-write-failed", "key", entry.Name)
		return "", false, err
	}
	if _, err := f.Write([]byte(data)); err != nil {
		f.Close()
		audit("pair-failed", "reason", "key-write-failed", "key", entry.Name)
		return "", false, err
	}
	if err := f.Close(); err != nil {
		audit("pair-failed", "reason", "key-write-failed", "key", entry.Name)
		return "", false, err
	}
	audit("pair-registered", "key", entry.Name, "replaced", strconv.FormatBool(replaced))
	return entry.Name, replaced, nil
}

// handlePair serves POST /v1/pair on the root-only unix socket: it mints a
// token for the requested phone name and answers with the token plus the TLS
// fingerprint and the numeric-IP host:port the phone must connect to.
func (pm *pairManager) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	token, err := pm.issue(req.Name)
	if err != nil {
		if err == errPairNotReady {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "pairing unavailable"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid name"})
		return
	}
	pm.mu.Lock()
	fp, host, port := pm.fp, pm.host, pm.port
	pm.mu.Unlock()
	writeJSON(w, http.StatusOK, struct {
		Token string `json:"token"`
		FP    string `json:"fp"`
		Host  string `json:"host"`
		Port  int    `json:"port"`
	}{Token: token, FP: fp, Host: host, Port: port})
}

// localIPv4 returns the numeric IPv4 the phone should dial first: the
// default-route interface address discovered by a best-effort UDP dial (the
// packet is never sent), falling back to the first non-loopback interface
// address, then loopback. It is a hostname-free address so a phone can
// connect without mDNS or DNS resolution.
func localIPv4() string {
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		defer conn.Close()
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if ip4 := ua.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}
