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

// newTestKeyProvider writes the given name→pubkey pairs into a fresh temp dir
// and returns a keyProvider rooted there. nil/empty keys yield a provider
// with zero paired keys.
func newTestKeyProvider(t *testing.T, keys map[string]ed25519.PublicKey) *keyProvider {
	t.Helper()
	dir := t.TempDir()
	for name, pub := range keys {
		writePub(t, dir, name, pub)
	}
	return newKeyProvider(dir)
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

// ---- keyProvider tests ----

func TestKeyProviderLookup(t *testing.T) {
	pubAlice, _ := newKey(t)
	pubBob, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pubAlice, "bob": pubBob})

	name, ok := kp.Lookup(pubAlice)
	if !ok || name != "alice" {
		t.Errorf("Lookup(alice) = %q, %v; want alice, true", name, ok)
	}
	name, ok = kp.Lookup(pubBob)
	if !ok || name != "bob" {
		t.Errorf("Lookup(bob) = %q, %v; want bob, true", name, ok)
	}
}

func TestKeyProviderLookupMiss(t *testing.T) {
	pubAlice, _ := newKey(t)
	unpaired, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pubAlice})

	if name, ok := kp.Lookup(unpaired); ok || name != "" {
		t.Errorf("Lookup(unpaired) = %q, %v; want \"\", false", name, ok)
	}
}

func TestKeyProviderCountAndAll(t *testing.T) {
	pubAlice, _ := newKey(t)
	pubBob, _ := newKey(t)
	kp := newTestKeyProvider(t, map[string]ed25519.PublicKey{"alice": pubAlice, "bob": pubBob})

	if got := kp.Count(); got != 2 {
		t.Errorf("Count() = %d, want 2", got)
	}
	all := kp.All()
	if len(all) != 2 {
		t.Errorf("len(All()) = %d, want 2", len(all))
	}
	if !bytes.Equal(all["alice"], pubAlice) || !bytes.Equal(all["bob"], pubBob) {
		t.Errorf("All() = %v, want alice and bob", all)
	}
}

// TestKeyProviderLazyReload: keys are re-read from disk on every call, so a
// remove takes effect on the next lookup without any reload call.
func TestKeyProviderLazyReload(t *testing.T) {
	dir := t.TempDir()
	kp := newKeyProvider(dir)
	pub, _ := newKey(t)

	if name, ok := kp.Lookup(pub); ok || name != "" {
		t.Fatalf("Lookup before pairing = %q, %v; want \"\", false", name, ok)
	}

	writePub(t, dir, "alice", pub)
	name, ok := kp.Lookup(pub)
	if !ok || name != "alice" {
		t.Fatalf("Lookup after pairing = %q, %v; want alice, true", name, ok)
	}

	if err := os.Remove(filepath.Join(dir, "alice.pub")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if name, ok := kp.Lookup(pub); ok || name != "" {
		t.Fatalf("Lookup after remove = %q, %v; want \"\", false", name, ok)
	}
	if got := kp.Count(); got != 0 {
		t.Errorf("Count() after remove = %d, want 0", got)
	}
}

// TestKeyProviderMissingDir: a missing keys dir must not panic and yields no
// keys (decide answers unpaired-key).
func TestKeyProviderMissingDir(t *testing.T) {
	kp := newKeyProvider(filepath.Join(t.TempDir(), "does-not-exist"))

	if got := kp.Count(); got != 0 {
		t.Errorf("Count() = %d, want 0", got)
	}
	if name, ok := kp.Lookup(make(ed25519.PublicKey, ed25519.PublicKeySize)); ok || name != "" {
		t.Errorf("Lookup = %q, %v; want \"\", false", name, ok)
	}
	if all := kp.All(); all == nil || len(all) != 0 {
		t.Errorf("All() = %v, want empty non-nil map", all)
	}
}
