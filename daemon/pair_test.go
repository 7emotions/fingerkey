package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestPairManager builds a pairManager rooted at a fresh temp keys dir
// with transport identity set, so issue() can mint tokens.
func newTestPairManager(t *testing.T) *pairManager {
	t.Helper()
	pm := newPairManager(t.TempDir())
	pm.setTransport("abcdef", "10.0.0.5", 4443)
	return pm
}

// dialPairLink wires one phoneLink over a net.Pipe against store/kp/pm; the
// test acts as the phone on the returned pipe side.
func dialPairLink(t *testing.T, store *Store, kp *keyProvider, pairs *pairManager) (daemonSide, phoneSide net.Conn) {
	t.Helper()
	daemonSide, phoneSide = net.Pipe()
	go newPhoneLink(daemonSide).run(store, kp, pairs)
	t.Cleanup(func() {
		daemonSide.Close()
		phoneSide.Close()
	})
	return daemonSide, phoneSide
}

// sendHelloToken writes a hello carrying the pairing token. The name field is
// deliberately a hostile value: the pairing flow must never trust it.
func sendHelloToken(t *testing.T, w io.Writer, pub ed25519.PublicKey, token string) {
	t.Helper()
	hello := frameJSON(map[string]string{
		"type":   "hello",
		"pubkey": base64.StdEncoding.EncodeToString(pub),
		"name":   "hostile-impersonation",
		"token":  token,
	})
	if err := writeFrame(w, hello); err != nil {
		t.Fatalf("writeFrame(hello): %v", err)
	}
}

// readRegistered reads and decodes the next frame, expecting registered.
func readRegistered(t *testing.T, r io.Reader) registeredFrame {
	t.Helper()
	payload, err := readFrame(r)
	if err != nil {
		t.Fatalf("readFrame(registered): %v", err)
	}
	var f registeredFrame
	if err := json.Unmarshal(payload, &f); err != nil {
		t.Fatalf("registered frame is not valid JSON: %v", err)
	}
	if f.Type != "registered" {
		t.Fatalf("type = %q, want %q", f.Type, "registered")
	}
	return f
}

// isNumericIPv4 reports whether s is a numeric IPv4 literal, not a hostname.
func isNumericIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// TestPairTokenOneTimeUse: a token must be consumable exactly once — the
// second consume of the same token is rejected even before expiry. This locks
// the atomic-consume contract (delete-before-validate under the mutex).
func TestPairTokenOneTimeUse(t *testing.T) {
	pm := newTestPairManager(t)
	token, err := pm.issue("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pub, _ := newKey(t)

	name, _, err := pm.consume(token, pub)
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if name != "alice" {
		t.Errorf("first consume name = %q, want %q", name, "alice")
	}
	if _, err := os.Stat(filepath.Join(pm.keysDir, "alice.pub")); err != nil {
		t.Fatalf("first consume must write alice.pub: %v", err)
	}

	if _, _, err := pm.consume(token, pub); err == nil {
		t.Fatal("second consume of a one-time token succeeded, want rejection")
	}
}

// TestPairTokenReplacesExisting: re-pairing a name that already has a key
// file must overwrite it and report replaced=true.
func TestPairTokenReplacesExisting(t *testing.T) {
	pm := newTestPairManager(t)
	pubOld, _ := newKey(t)
	writePub(t, pm.keysDir, "alice", pubOld)

	token, err := pm.issue("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pubNew, _ := newKey(t)
	name, replaced, err := pm.consume(token, pubNew)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if name != "alice" || !replaced {
		t.Errorf("consume = %q, replaced=%v; want alice, replaced=true", name, replaced)
	}
	onDisk := loadPubKeys(pm.keysDir)
	if len(onDisk) != 1 {
		t.Fatalf("keys on disk = %d, want 1", len(onDisk))
	}
	if !onDisk["alice"].Equal(pubNew) {
		t.Errorf("alice.pub holds the old key; want the new one")
	}
}

// TestPairTokenExpired: a token past its TTL must be rejected without
// registering the key.
func TestPairTokenExpired(t *testing.T) {
	pm := newTestPairManager(t)
	token, err := pm.issue("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pm.mu.Lock()
	for k := range pm.tokens {
		pm.tokens[k] = pairingEntry{Name: pm.tokens[k].Name, Expires: time.Now().Add(-time.Second)}
	}
	pm.mu.Unlock()

	pub, _ := newKey(t)
	if _, _, err := pm.consume(token, pub); err == nil {
		t.Fatal("consume of an expired token succeeded, want rejection")
	}
	if _, err := os.Stat(filepath.Join(pm.keysDir, "alice.pub")); !os.IsNotExist(err) {
		t.Fatal("expired token must not write a key file")
	}
}

// TestPairTokenUnknown: a random token must be rejected.
func TestPairTokenUnknown(t *testing.T) {
	pm := newTestPairManager(t)
	pub, _ := newKey(t)
	if _, _, err := pm.consume("ffffffffffffffffffffffffffffffff", pub); err == nil {
		t.Fatal("consume of an unknown token succeeded, want rejection")
	}
}

// TestPairTokenRejectsBadNames: issue refuses names that cannot become a safe
// <name>.pub filename.
func TestPairTokenRejectsBadNames(t *testing.T) {
	pm := newTestPairManager(t)
	for _, name := range []string{"", "a/b", "..", ".", "a\\b"} {
		if _, err := pm.issue(name); err == nil {
			t.Errorf("issue(%q) succeeded, want rejection", name)
		}
	}
	if _, err := pm.issue("pixel-8"); err != nil {
		t.Errorf("issue(pixel-8) failed, want success: %v", err)
	}
}

// TestPairConsumeRefusesSymlink: a symlink planted at <name>.pub pointing at
// an arbitrary file must be refused, not followed — the target's bytes must
// survive the consume attempt untouched (CWE-59).
func TestPairConsumeRefusesSymlink(t *testing.T) {
	pm := newTestPairManager(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("SENTINEL"), 0600); err != nil {
		t.Fatalf("write sentinel target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(pm.keysDir, "alice.pub")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	token, err := pm.issue("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pub, _ := newKey(t)
	if _, _, err := pm.consume(token, pub); err == nil {
		t.Fatal("consume followed a symlinked key path, want refusal")
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read sentinel target: %v", err)
	}
	if string(got) != "SENTINEL" {
		t.Fatalf("target bytes = %q, want SENTINEL (not truncated/overwritten)", got)
	}
}

// TestPairTokenCleanup: issue purges expired tokens, so the map does not grow
// unboundedly across pairing windows.
func TestPairTokenCleanup(t *testing.T) {
	pm := newTestPairManager(t)
	old := pairTTL
	pairTTL = 10 * time.Millisecond
	defer func() { pairTTL = old }()

	if _, err := pm.issue("alice"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := pm.issue("bob"); err != nil {
		t.Fatalf("issue: %v", err)
	}

	pm.mu.Lock()
	n := len(pm.tokens)
	pm.mu.Unlock()
	if n != 1 {
		t.Errorf("tokens after purge = %d, want 1 (only bob's live token)", n)
	}
}

// TestPairConsumeAudits: a consumed token audits pair-registered, and a
// replaced key audits replaced=true; a failed token audits pair-failed.
func TestPairConsumeAudits(t *testing.T) {
	buf := swapAudit(t)
	pm := newTestPairManager(t)
	pub, _ := newKey(t)

	token, err := pm.issue("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := pm.consume(token, pub); err != nil {
		t.Fatalf("consume: %v", err)
	}
	auditMu.Lock()
	got := buf.String()
	auditMu.Unlock()
	if !strings.Contains(got, "event=pair-registered") || !strings.Contains(got, "key=alice") {
		t.Fatalf("pair-registered audit missing: %q", got)
	}

	if _, _, err := pm.consume(token, pub); err == nil {
		t.Fatal("replay consumed, want rejection")
	}
	auditMu.Lock()
	got = buf.String()
	auditMu.Unlock()
	if !strings.Contains(got, "event=pair-failed") {
		t.Fatalf("pair-failed audit missing: %q", got)
	}
}

// TestPairIssueTokenFormat: issue returns a fresh random hex token.
func TestPairIssueTokenFormat(t *testing.T) {
	pm := newTestPairManager(t)
	t1, err := pm.issue("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	t2, err := pm.issue("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if t1 == t2 {
		t.Fatal("two issues returned the same token")
	}
	for _, tok := range []string{t1, t2} {
		if len(tok) != 32 {
			t.Errorf("token %q has length %d, want 32 hex chars", tok, len(tok))
		}
		if _, err := hex.DecodeString(tok); err != nil {
			t.Errorf("token %q is not hex: %v", tok, err)
		}
	}
}

// TestHandlePairResponseFields: POST /v1/pair returns a one-time token plus
// the fingerprint, a numeric-IP host (never a hostname) and the TLS port.
func TestHandlePairResponseFields(t *testing.T) {
	store := NewStore()
	pm := newPairManager(t.TempDir())
	pm.setTransport("abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1", "10.2.3.4", 4443)
	local := httptest.NewServer(newLocalMux(store, newTestKeyProvider(t, nil), pm))
	defer local.Close()

	resp := postJSON(t, local.URL+"/v1/pair", `{"name":"pixel-8"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	token, _ := m["token"].(string)
	if len(token) != 32 {
		t.Errorf("token = %q, want 32 hex chars", token)
	}
	if _, err := hex.DecodeString(token); err != nil {
		t.Errorf("token %q is not hex: %v", token, err)
	}
	if fp, _ := m["fp"].(string); fp != "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1" {
		t.Errorf("fp = %q, want the advertised fingerprint", fp)
	}
	if host, _ := m["host"].(string); !isNumericIPv4(host) {
		t.Errorf("host = %q, want a numeric IPv4 literal", host)
	}
	if port, ok := m["port"].(float64); !ok || port != 4443 {
		t.Errorf("port = %v, want 4443", m["port"])
	}

	req, _ := http.NewRequest(http.MethodGet, local.URL+"/v1/pair", nil)
	rresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/pair: %v", err)
	}
	rresp.Body.Close()
	if rresp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /v1/pair = %d, want 404", rresp.StatusCode)
	}
}

// TestHandlePairNotReady: before the TLS listener is up, POST /v1/pair must
// refuse with 503 instead of advertising a dead endpoint.
func TestHandlePairNotReady(t *testing.T) {
	store := NewStore()
	pm := newPairManager(t.TempDir()) // transport never set
	local := httptest.NewServer(newLocalMux(store, newTestKeyProvider(t, nil), pm))
	defer local.Close()

	resp := postJSON(t, local.URL+"/v1/pair", `{"name":"pixel-8"}`)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if m := decodeJSON(t, resp); m["error"] != "pairing unavailable" {
		t.Errorf("body = %v, want error pairing unavailable", m)
	}
}

// TestHandlePairBadName: an unsafe name is rejected with 400.
func TestHandlePairBadName(t *testing.T) {
	store := NewStore()
	pm := newTestPairManager(t)
	local := httptest.NewServer(newLocalMux(store, newTestKeyProvider(t, nil), pm))
	defer local.Close()

	resp := postJSON(t, local.URL+"/v1/pair", `{"name":"../evil"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestPhoneLinkTokenRegistration: a hello carrying a valid token registers
// under the TOKEN's name (never the hello's name), writes <name>.pub, and is
// answered with registered{key:name}.
func TestPhoneLinkTokenRegistration(t *testing.T) {
	waitNoLinks(t)
	pm := newTestPairManager(t)
	store := NewStore()
	pub, _ := newKey(t)
	keys := newKeyProvider(pm.keysDir)

	token, err := pm.issue("pixel-8")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, phoneSide := dialPairLink(t, store, keys, pm)
	sendHelloToken(t, phoneSide, pub, token)

	reg := readRegistered(t, phoneSide)
	if reg.Key != "pixel-8" {
		t.Fatalf("registered.key = %q, want the token's name pixel-8 (hello.name is display-only)", reg.Key)
	}
	if _, err := os.Stat(filepath.Join(pm.keysDir, "pixel-8.pub")); err != nil {
		t.Fatalf("registration must write pixel-8.pub: %v", err)
	}
	if !phoneConnected() {
		t.Fatal("token-registered link must count as connected")
	}
}

// TestPhoneLinkTokenRegisteredReceivesPendingAndDecides: the token path
// treats the link as registered — it receives live pending pushes and can
// decide them, because consume() wrote a key file that keyProvider re-reads.
func TestPhoneLinkTokenRegisteredReceivesPendingAndDecides(t *testing.T) {
	pm := newTestPairManager(t)
	store := NewStore()
	pub, priv := newKey(t)
	keys := newKeyProvider(pm.keysDir)

	token, err := pm.issue("pixel-8")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, phoneSide := dialPairLink(t, store, keys, pm)
	sendHelloToken(t, phoneSide, pub, token)
	if reg := readRegistered(t, phoneSide); reg.Key != "pixel-8" {
		t.Fatalf("registered.key = %q, want pixel-8", reg.Key)
	}

	s, err := store.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	payload, err := readFrame(phoneSide)
	if err != nil {
		t.Fatalf("readFrame(pending): %v", err)
	}
	var f pendingFrame
	if err := json.Unmarshal(payload, &f); err != nil {
		t.Fatalf("pending frame is not valid JSON: %v", err)
	}
	if f.ID != s.ID {
		t.Errorf("pending id = %q, want %q", f.ID, s.ID)
	}

	decision, err := json.Marshal(map[string]string{
		"type":     "decision",
		"id":       s.ID,
		"decision": "approve",
		"sig":      signDecision(priv, "approve", s),
	})
	if err != nil {
		t.Fatalf("marshal decision: %v", err)
	}
	if err := writeFrame(phoneSide, decision); err != nil {
		t.Fatalf("writeFrame(decision): %v", err)
	}
	payload, err = readFrame(phoneSide)
	if err != nil {
		t.Fatalf("readFrame(result): %v", err)
	}
	var res decisionResultFrame
	if err := json.Unmarshal(payload, &res); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if res.Status != StatusApproved || res.Key != "pixel-8" {
		t.Errorf("result = %+v, want approved by pixel-8", res)
	}
}

// TestPhoneLinkTokenSecondUseRejected: the second hello carrying the same
// token is refused with welcome{registered:false} and audited pair-failed —
// the token is one-time end to end.
func TestPhoneLinkTokenSecondUseRejected(t *testing.T) {
	buf := swapAudit(t)
	waitNoLinks(t)
	pm := newTestPairManager(t)
	store := NewStore()
	pub1, _ := newKey(t)
	keys := newKeyProvider(pm.keysDir)

	token, err := pm.issue("pixel-8")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, phone1 := dialPairLink(t, store, keys, pm)
	sendHelloToken(t, phone1, pub1, token)
	if reg := readRegistered(t, phone1); reg.Key != "pixel-8" {
		t.Fatalf("first link registered.key = %q, want pixel-8", reg.Key)
	}

	pub2, _ := newKey(t)
	_, phone2 := dialPairLink(t, store, keys, pm)
	sendHelloToken(t, phone2, pub2, token)
	w := readWelcome(t, phone2)
	if w.Registered {
		t.Fatal("second use of a one-time token must be refused")
	}
	phone2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFrame(phone2); err == nil {
		t.Fatal("rejected pairing link must be closed")
	}

	auditMu.Lock()
	got := buf.String()
	auditMu.Unlock()
	if !strings.Contains(got, "event=pair-failed") {
		t.Fatalf("pair-failed audit missing: %q", got)
	}
}
