package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePub writes pub to <name>.pub in dir in the daemon's on-disk format:
// standard padded base64 of the 32-byte Ed25519 public key.
func writePub(t *testing.T, dir, name string, pub ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join(dir, name+".pub")
	data := base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// TestLoadPubKeysNames: alice.pub + bob.pub load to a 2-entry map keyed by the
// filename with the .pub suffix stripped.
func TestLoadPubKeysNames(t *testing.T) {
	dir := t.TempDir()
	pubAlice, _ := newKey(t)
	pubBob, _ := newKey(t)
	writePub(t, dir, "alice", pubAlice)
	writePub(t, dir, "bob", pubBob)

	keys := loadPubKeys(dir)

	if len(keys) != 2 {
		t.Fatalf("len(keys) = %d, want 2", len(keys))
	}
	if got := keys["alice"]; !bytes.Equal(got, pubAlice) {
		t.Errorf("keys[alice] = %x, want %x", got, pubAlice)
	}
	if got := keys["bob"]; !bytes.Equal(got, pubBob) {
		t.Errorf("keys[bob] = %x, want %x", got, pubBob)
	}
}

// TestLoadPubKeysSkipsCorrupt: a 1-byte .pub file is not a padded base64
// 32-byte key, so it is skipped with a warning naming the file.
func TestLoadPubKeysSkipsCorrupt(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "carol.pub"), []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keys := loadPubKeys(dir)

	if len(keys) != 0 {
		t.Fatalf("len(keys) = %d, want 0 (corrupt key must be skipped)", len(keys))
	}
	if _, ok := keys["carol"]; ok {
		t.Error("corrupt carol.pub must not appear in the map")
	}
	if !strings.Contains(buf.String(), "skipping") || !strings.Contains(buf.String(), "carol.pub") {
		t.Errorf("want a warning naming carol.pub, got: %q", buf.String())
	}
}

// TestLoadPubKeysMissingDir: a missing directory yields an empty, non-nil map.
func TestLoadPubKeysMissingDir(t *testing.T) {
	keys := loadPubKeys(filepath.Join(t.TempDir(), "does-not-exist"))

	if keys == nil {
		t.Fatal("missing dir must yield an empty, non-nil map")
	}
	if len(keys) != 0 {
		t.Fatalf("len(keys) = %d, want 0", len(keys))
	}
}
