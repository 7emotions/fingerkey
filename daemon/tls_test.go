package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genTestCert generates a self-signed Ed25519 server certificate valid for
// 127.0.0.1 and writes PEM cert + PKCS#8 key to temp files, returning their
// paths. Mirrors what a deployment would put in /etc/phone-fprint-auth/.
func genTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "phone-fprint-auth test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	return certFile, keyFile
}

// TestTLSLoadConfigMissingFile: a nonexistent cert file must fail loadTLSConfig.
func TestTLSLoadConfigMissingFile(t *testing.T) {
	if _, err := loadTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Fatal("loadTLSConfig with nonexistent files must return an error")
	}
}

// TestTLSLoadConfigValid: a real keypair loads, enforces TLS >= 1.2, and does
// NOT override CipherSuites (Go's default policy applies).
func TestTLSLoadConfigValid(t *testing.T) {
	certFile, keyFile := genTestCert(t)
	cfg, err := loadTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.CipherSuites) != 0 {
		t.Errorf("CipherSuites = %v, want empty (trust Go's default policy)", cfg.CipherSuites)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d entries, want 1", len(cfg.Certificates))
	}
}

// TestTLSPhoneSurfaceE2E serves newPhoneMux behind tls.NewListener on a real
// TCP listener and GETs /healthz over HTTPS, proving the phone surface works
// end-to-end when wrapped in TLS exactly as main() wraps it.
func TestTLSPhoneSurfaceE2E(t *testing.T) {
	certFile, keyFile := genTestCert(t)
	cfg, err := loadTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}

	store := NewStore()
	keys := map[string]ed25519.PublicKey{}
	phoneLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &http.Server{Handler: newPhoneMux(store, keys)}
	go srv.Serve(tls.NewListener(phoneLn, cfg))
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + phoneLn.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("GET https /healthz: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}
