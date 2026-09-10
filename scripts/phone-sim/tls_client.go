package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// dialTimeout bounds the TCP connect; clientHandshakeTimeout bounds the TLS
// handshake from the client side (the daemon independently caps handshakes at
// ~10s server-side).
const (
	dialTimeout            = 10 * time.Second
	clientHandshakeTimeout = 10 * time.Second
)

// fingerprintMismatchError reports a server whose leaf certificate DER does
// not hash to the pinned fingerprint. It is a terminal error: main exits
// instead of retrying, because retrying cannot change the server's identity.
type fingerprintMismatchError struct {
	Want string // pinned fingerprint, lowercase hex
	Got  string // what the server actually presented
}

func (e *fingerprintMismatchError) Error() string {
	return fmt.Sprintf("server certificate fingerprint mismatch: want %s, got %s", e.Want, e.Got)
}

// dialTLS connects to addr over TLS and pins the server identity: the leaf
// certificate's DER form must hash (SHA-256, lowercase hex) to fp. Hostname
// and chain verification are deliberately skipped — the daemon's certificate
// is self-signed, so there is no chain to trust — but verification is never
// skipped entirely: verifyServerCert always asserts the fingerprint, so a
// wrong or missing pin fails the handshake instead of connecting to an
// unpinned server.
func dialTLS(addr string, fp [32]byte) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		MinVersion:            tls.VersionTLS12,
		InsecureSkipVerify:    true, // chain/hostname checks replaced by the fingerprint pin below
		VerifyPeerCertificate: verifyServerCert(fp),
	})
	_ = conn.SetDeadline(time.Now().Add(clientHandshakeTimeout))
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// verifyServerCert returns the VerifyPeerCertificate callback that pins the
// leaf certificate: rawCerts[0] is the leaf's DER form, the same bytes the
// daemon hashes for its advertised fingerprint (daemon/tls.go certFingerprint).
func verifyServerCert(fp [32]byte) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return &fingerprintMismatchError{Want: hex.EncodeToString(fp[:]), Got: "<no certificate>"}
		}
		got := sha256.Sum256(rawCerts[0])
		if !bytes.Equal(got[:], fp[:]) {
			return &fingerprintMismatchError{
				Want: hex.EncodeToString(fp[:]),
				Got:  hex.EncodeToString(got[:]),
			}
		}
		return nil
	}
}
