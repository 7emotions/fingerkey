// Command phone-sim is the phone simulator for phone-fprint-auth. It
// long-polls the daemon's /v1/pending endpoint and, for every pending
// session, builds the pinned signed message with the session's nonce, signs
// it with the given Ed25519 private key, and POSTs the decision back to the
// daemon. It keeps polling after every response.
//
// Usage:
//
//	phone-sim -key <priv_b64> [-action approve|deny] [-url http://127.0.0.1:8766]
//
// <priv_b64> is the standard, padded base64 encoding of a 64-byte Ed25519
// private key; -action defaults to "approve".
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"phonefprint/scripts/format"
)

// pollTimeout exceeds the daemon's maximum long-poll hold (60s) so a pending
// poll is never cut short by the client.
const pollTimeout = 75 * time.Second

func main() {
	keyB64 := flag.String("key", "", "base64 (standard, padded) Ed25519 private key")
	action := flag.String("action", "approve", "decision to send: approve or deny")
	baseURL := flag.String("url", "http://127.0.0.1:8766", "daemon base URL")
	flag.Parse()

	if *keyB64 == "" {
		log.Fatal("phone-sim: -key is required")
	}
	priv, err := decodePriv(*keyB64)
	if err != nil {
		log.Fatalf("phone-sim: %v", err)
	}
	if *action != "approve" && *action != "deny" {
		log.Fatalf("phone-sim: -action must be approve or deny, got %q", *action)
	}
	base := strings.TrimRight(*baseURL, "/")

	client := &http.Client{Timeout: pollTimeout}
	for {
		if err := pollOnce(client, base, *action, priv); err != nil {
			log.Printf("phone-sim: %v (retrying in 2s)", err)
			time.Sleep(2 * time.Second)
		}
	}
}

// decodePriv decodes the standard padded base64 private key and checks its
// length (64 bytes for Ed25519).
func decodePriv(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("invalid private key: not standard padded base64: %v", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key: decoded %d bytes, want %d (Ed25519)", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// pending is the body of a 200 /v1/pending response.
type pending struct {
	ID      string `json:"id"`
	Nonce   string `json:"nonce"`
	User    string `json:"user"`
	Service string `json:"service"`
	TTY     string `json:"tty"`
}

// pollOnce performs one long-poll cycle: it waits up to 60s for a pending
// session and, if one arrives, signs and posts the decision. Any error is
// returned to the caller, which retries after a short pause.
func pollOnce(client *http.Client, base, action string, priv ed25519.PrivateKey) error {
	resp, err := client.Get(base + "/v1/pending?wait=60")
	if err != nil {
		return fmt.Errorf("poll failed: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		fmt.Println("poll: no pending session")
		return nil
	case http.StatusOK:
		// a session arrived — fall through to handle it
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("poll returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var p pending
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return fmt.Errorf("cannot decode pending session: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(p.Nonce)
	if err != nil || len(nonce) != 32 {
		return fmt.Errorf("session %s: bad nonce in pending response", p.ID)
	}

	msg := format.SignedMessage(action, p.User, p.Service, p.TTY, nonce)
	sig := ed25519.Sign(priv, msg)
	body, err := json.Marshal(struct {
		Decision string `json:"decision"`
		Sig      string `json:"sig"`
	}{action, base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return err
	}

	post, err := client.Post(base+"/v1/session/"+p.ID+"/decision", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("session %s: decision POST failed: %v", p.ID, err)
	}
	defer post.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(post.Body, 4096))
	fmt.Printf("session %s user=%q service=%q tty=%q: sent %s -> HTTP %d %s\n",
		p.ID, p.User, p.Service, p.TTY, action, post.StatusCode, strings.TrimSpace(string(respBody)))
	return nil
}
