package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// tlsIdentityFiles are the cert/key filenames inside -tls-dir. install.sh
// pre-generates the same pair (owned by phonefprint); the daemon regenerates
// it only when it is missing or unloadable.
const (
	tlsCertFile = "cert.pem"
	tlsKeyFile  = "key.pem"
)

// certValidity is the self-signed certificate lifetime (~3650 days).
var certValidity = 3650 * 24 * time.Hour

// handshakeTimeout bounds the TLS handshake per connection, so a slow-loris
// ClientHello cannot occupy a conn slot forever. Package var for tests.
var handshakeTimeout = 10 * time.Second

// loadOrGenerateTLSIdentity loads the daemon's server identity from tlsDir.
// When the pair is missing or unloadable it generates a fresh self-signed
// ECDSA P-256 certificate (CN=phone-fprint-auth), writes it back 0644/0600,
// and audits tls-identity-regenerated. It returns the certificate and the
// lowercase-hex SHA-256 fingerprint of its DER form — the phone-pinned
// server identity.
func loadOrGenerateTLSIdentity(tlsDir string) (tls.Certificate, string, error) {
	certPath := filepath.Join(tlsDir, tlsCertFile)
	keyPath := filepath.Join(tlsDir, tlsKeyFile)
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, certFingerprint(cert), nil
	}
	cert, err := generateTLSIdentity(tlsDir)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	audit("tls-identity-regenerated", "dir", tlsDir)
	return cert, certFingerprint(cert), nil
}

// generateTLSIdentity creates the self-signed server identity and persists it
// into tlsDir (dir 0700, cert 0644, key 0600).
func generateTLSIdentity(tlsDir string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "phone-fprint-auth"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed: its own issuer
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(tlsDir, tlsCertFile), certPEM, 0644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(filepath.Join(tlsDir, tlsKeyFile), keyPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// certFingerprint is the lowercase-hex SHA-256 of the certificate's DER form:
// the stable server identity the phone pins and mDNS advertises.
func certFingerprint(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// connTracker counts live TLS connections, in total and per remote IP, so the
// limits can be enforced at ACCEPT time before any handshake work.
type connTracker struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
}

func newConnTracker() *connTracker {
	return &connTracker{perIP: make(map[string]int)}
}

// acquire reserves one slot for ip under both limits and reports whether the
// reservation succeeded.
func (ct *connTracker) acquire(ip string, maxTotal, maxPerIP int) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.total >= maxTotal || ct.perIP[ip] >= maxPerIP {
		return false
	}
	ct.total++
	ct.perIP[ip]++
	return true
}

// release frees the slot reserved by acquire.
func (ct *connTracker) release(ip string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.total > 0 {
		ct.total--
	}
	if n := ct.perIP[ip]; n > 1 {
		ct.perIP[ip] = n - 1
	} else {
		delete(ct.perIP, ip)
	}
}

// trackedConn wraps an accepted TLS connection so that its slot in the
// connTracker is released exactly once when the connection closes — whichever
// path closes it (handshake failure, phone-link teardown, idle timeout).
type trackedConn struct {
	*tls.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// serveTLS listens on addr and hands every accepted TLS connection to
// startPhoneLink. Connections are counted at ACCEPT time against maxConns
// and maxConnsPerIP; an over-limit accept is audited as conn-limit and closed
// immediately. Each handshake is bounded by handshakeTimeout via
// HandshakeContext; TCP keepalive is enabled on the raw socket before TLS.
// The returned listener must be closed by the caller to stop accepting.
func serveTLS(addr string, cert tls.Certificate, maxConns, maxConnsPerIP int, store *Store, keys *keyProvider, pairs *pairManager) (net.Listener, error) {
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	tracker := newConnTracker()
	// Capture the timeout once: per-connection goroutines must never read the
	// package var, which tests mutate while listeners from earlier tests are
	// still shutting down.
	hsTimeout := handshakeTimeout
	go func() {
		for {
			raw, err := tcpLn.Accept()
			if err != nil {
				return
			}
			ip := remoteIP(raw)
			if !tracker.acquire(ip, maxConns, maxConnsPerIP) {
				audit("conn-limit", "ip", ip)
				raw.Close()
				continue
			}
			if tc, ok := raw.(*net.TCPConn); ok {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(15 * time.Second)
			}
			tlsConn := tls.Server(raw, cfg)
			tracked := &trackedConn{Conn: tlsConn, release: func() { tracker.release(ip) }}
			go handleTLSConn(tracked, hsTimeout, store, keys, pairs)
		}
	}()
	return tcpLn, nil
}

// handleTLSConn bounds the handshake and hands the established TLS stream to
// the phone-link lifecycle. Closing the conn — here or later inside the link
// — releases the tracker slot via trackedConn.Close.
func handleTLSConn(conn *trackedConn, hsTimeout time.Duration, store *Store, keys *keyProvider, pairs *pairManager) {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), hsTimeout)
	err := conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	startPhoneLink(conn, store, keys, pairs)
}

// remoteIP extracts the peer's IP string for per-IP accounting.
func remoteIP(c net.Conn) string {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	return ""
}
