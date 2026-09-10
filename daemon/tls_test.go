package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

var hexFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestCertFingerprintStableLowercaseHex: the fingerprint is the lowercase-hex
// SHA-256 of the DER certificate and is stable across reloads of the same
// identity — the property that lets a phone pin it.
func TestCertFingerprintStableLowercaseHex(t *testing.T) {
	dir := t.TempDir()
	cert, fp1, err := loadOrGenerateTLSIdentity(dir)
	if err != nil {
		t.Fatalf("loadOrGenerateTLSIdentity: %v", err)
	}
	if !hexFingerprint.MatchString(fp1) {
		t.Fatalf("fingerprint %q is not 64 lowercase hex chars", fp1)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	if want := hex.EncodeToString(sum[:]); fp1 != want {
		t.Errorf("fingerprint %q != sha256(DER) %q", fp1, want)
	}

	// A second load reads the persisted identity: same fingerprint, no
	// regeneration.
	if _, fp2, err := loadOrGenerateTLSIdentity(dir); err != nil {
		t.Fatalf("second load: %v", err)
	} else if fp2 != fp1 {
		t.Errorf("fingerprint changed across reloads: %q → %q", fp1, fp2)
	}
}

// TestTLSAuditsIdentityRegenerated: a missing identity is generated on first
// load and audited as tls-identity-regenerated.
func TestTLSAuditsIdentityRegenerated(t *testing.T) {
	buf := swapAudit(t)
	dir := t.TempDir()
	if _, _, err := loadOrGenerateTLSIdentity(dir); err != nil {
		t.Fatalf("loadOrGenerateTLSIdentity: %v", err)
	}
	auditMu.Lock()
	got := buf.String()
	auditMu.Unlock()
	if !strings.Contains(got, "event=tls-identity-regenerated") {
		t.Fatalf("tls-identity-regenerated audit missing: %q", got)
	}
}

// TestTLSListenerHandshakeFingerprint: a real TLS handshake against the
// listener presents exactly the loaded certificate — the peer DER fingerprint
// equals the advertised one.
func TestTLSListenerHandshakeFingerprint(t *testing.T) {
	store := NewStore()
	keys := newTestKeyProvider(t, nil)
	cert, fp, err := loadOrGenerateTLSIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("loadOrGenerateTLSIdentity: %v", err)
	}
	ln, err := serveTLS("127.0.0.1:0", cert, 16, 4, store, keys, nil)
	if err != nil {
		t.Fatalf("serveTLS: %v", err)
	}
	defer ln.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) != 1 {
		t.Fatalf("peer certificates = %d, want 1", len(state.PeerCertificates))
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if got := hex.EncodeToString(sum[:]); got != fp {
		t.Errorf("peer cert fingerprint = %q, want %q", got, fp)
	}
}

// TestConnLimitRejectedAtAccept: with maxConns=1 the second accepted
// connection is closed before any handshake work and audited conn-limit.
func TestConnLimitRejectedAtAccept(t *testing.T) {
	buf := swapAudit(t)
	store := NewStore()
	keys := newTestKeyProvider(t, nil)
	cert, _, err := loadOrGenerateTLSIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("loadOrGenerateTLSIdentity: %v", err)
	}
	ln, err := serveTLS("127.0.0.1:0", cert, 1, 4, store, keys, nil)
	if err != nil {
		t.Fatalf("serveTLS: %v", err)
	}
	defer ln.Close()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.Close()

	// The accept loop is sequential: c1 is accepted and counted before c2 is
	// accepted, so c2 deterministically hits the limit.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit connection must be closed by the server")
	}

	auditMu.Lock()
	got := buf.String()
	auditMu.Unlock()
	if !strings.Contains(got, "event=conn-limit") {
		t.Fatalf("conn-limit audit missing: %q", got)
	}
}

// TestConnLimitPerIPRejectedAndReleased: with maxConnsPerIP=1 a second
// connection from the same IP is rejected, and once the first closes its slot
// is released — a new connection is accepted again.
func TestConnLimitPerIPRejectedAndReleased(t *testing.T) {
	store := NewStore()
	keys := newTestKeyProvider(t, nil)
	cert, _, err := loadOrGenerateTLSIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("loadOrGenerateTLSIdentity: %v", err)
	}
	ln, err := serveTLS("127.0.0.1:0", cert, 16, 1, store, keys, nil)
	if err != nil {
		t.Fatalf("serveTLS: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}

	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("second conn from the same IP must be rejected under maxConnsPerIP=1")
	}

	// Close c1: its slot is released, so a fresh conn must now be accepted
	// (the server holds it open waiting for a handshake instead of closing
	// it).
	if err := c1.Close(); err != nil {
		t.Fatalf("close c1: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial probe: %v", err)
		}
		probe.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		_, rerr := probe.Read(make([]byte, 1))
		probe.Close()
		if rerr == nil {
			t.Fatal("probe read returned nil error, want EOF or timeout")
		}
		if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
			break // read timed out: the conn is held open → within limit
		}
		if time.Now().After(deadline) {
			t.Fatal("per-IP slot never released after c1 closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTLSHandshakeTimeoutCloses: a connection that never completes the TLS
// handshake is closed after handshakeTimeout, so a slow-loris ClientHello
// cannot hold a slot forever.
func TestTLSHandshakeTimeoutCloses(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 200 * time.Millisecond
	defer func() { handshakeTimeout = old }()

	store := NewStore()
	keys := newTestKeyProvider(t, nil)
	cert, _, err := loadOrGenerateTLSIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("loadOrGenerateTLSIdentity: %v", err)
	}
	ln, err := serveTLS("127.0.0.1:0", cert, 16, 4, store, keys, nil)
	if err != nil {
		t.Fatalf("serveTLS: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent connection must be closed after handshakeTimeout")
	}
}
