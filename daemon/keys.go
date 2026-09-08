package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// loadPubKeys reads every <name>.pub file in dir and decodes each file as a
// standard, padded base64 encoding of a 32-byte Ed25519 public key. The
// returned map is keyed by the <name>.pub filename with the .pub suffix
// stripped, so a verified decision can be attributed to the key's name in
// audit logging. Files that fail to decode are skipped with a warning so one
// bad key cannot take the daemon down. A missing directory yields an empty
// map — with no keys paired, every /decision is 401.
func loadPubKeys(dir string) map[string]ed25519.PublicKey {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("keys: %s does not exist — no keys paired", dir)
		} else {
			log.Printf("keys: cannot read %s: %v", dir, err)
		}
		return map[string]ed25519.PublicKey{}
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("keys: cannot read %s: %v", path, err)
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			log.Printf("keys: skipping %s: not a padded base64 Ed25519 public key", path)
			continue
		}
		keys[strings.TrimSuffix(e.Name(), ".pub")] = ed25519.PublicKey(raw)
	}
	return keys
}
