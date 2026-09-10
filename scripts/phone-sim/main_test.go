package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// testServerCert generates the same self-signed ECDSA P-256 identity the
// daemon uses, returning the certificate and its pinned fingerprint.
func testServerCert(t *testing.T) (tls.Certificate, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "phone-fprint-auth"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	fp := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fp
}

// TestVerifyServerCertOK: the callback accepts the exact pinned fingerprint.
func TestVerifyServerCertOK(t *testing.T) {
	cert, fp := testServerCert(t)
	if err := verifyServerCert(fp)(cert.Certificate, nil); err != nil {
		t.Fatalf("verifyServerCert with matching fingerprint: %v", err)
	}
}

// TestVerifyServerCertWrongFP: a different fingerprint must be refused with a
// fingerprintMismatchError carrying both hashes.
func TestVerifyServerCertWrongFP(t *testing.T) {
	cert, fp := testServerCert(t)
	fp[0] ^= 0xff
	var fpErr *fingerprintMismatchError
	err := verifyServerCert(fp)(cert.Certificate, nil)
	if !errors.As(err, &fpErr) {
		t.Fatalf("wrong fingerprint: got %v, want fingerprintMismatchError", err)
	}
	if fpErr.Want == "" || fpErr.Got == "" {
		t.Fatalf("fingerprintMismatchError must carry want and got, got %+v", fpErr)
	}
}

// TestVerifyServerCertNoCerts: an empty certificate chain is a mismatch, not
// a silent pass.
func TestVerifyServerCertNoCerts(t *testing.T) {
	var fp [32]byte
	var fpErr *fingerprintMismatchError
	err := verifyServerCert(fp)(nil, nil)
	if !errors.As(err, &fpErr) {
		t.Fatalf("empty certs: got %v, want fingerprintMismatchError", err)
	}
}

// TestDialTLSFingerprintPin runs a real handshake against a self-signed
// server: the right pin connects and the connection is a usable TLS stream;
// the wrong pin fails the handshake with a fingerprintMismatchError instead
// of connecting to the unpinned server.
func TestDialTLSFingerprintPin(t *testing.T) {
	cert, fp := testServerCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()
	served := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tlsConn := conn.(*tls.Conn)
				_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := tlsConn.Handshake(); err == nil {
					select {
					case served <- struct{}{}:
					default:
					}
				}
				_ = conn.Close()
			}()
		}
	}()
	addr := ln.Addr().String()

	conn, err := dialTLS(addr, fp)
	if err != nil {
		t.Fatalf("dialTLS with matching fingerprint: %v", err)
	}
	_ = conn.Close()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("server never completed a handshake")
	}

	badFP := fp
	badFP[0] ^= 0xff
	conn, err = dialTLS(addr, badFP)
	if err == nil {
		_ = conn.Close()
		t.Fatal("dialTLS with wrong fingerprint must fail")
	}
	var fpErr *fingerprintMismatchError
	if !errors.As(err, &fpErr) {
		t.Fatalf("wrong fingerprint: got %v, want fingerprintMismatchError", err)
	}
}
