// Command phone-sim is the phone simulator for phone-fprint-auth. It dials
// the daemon's TLS phone listener (-addr), pins the server by its certificate
// fingerprint (-fp), and speaks the same framed protocol as the production
// phone: hello on connect, then the daemon pushes pending frames and the sim
// builds the pinned signed message with the session's nonce, signs it with
// the given Ed25519 private key, and answers with a decision frame. It keeps
// listening after every answer unless -once, and sends a ping every 15s so
// the daemon's idle timer never kills a silent-but-healthy link.
//
// Usage:
//
//	phone-sim -addr <host:port> -fp <hex> -key <priv_b64> [-decision approve|deny|hold] [-once]
//	phone-sim -keygen
//
// <fp> is the lowercase hex SHA-256 of the daemon certificate's DER form (as
// logged by the daemon at startup); <priv_b64> is the standard, padded base64
// encoding of a 64-byte Ed25519 private key. -decision defaults to "approve";
// "hold" keeps the link alive but never answers a pending request (used by
// the timeout E2E). -keygen prints a fresh "<priv_b64> <pub_b64>" pair and
// exits.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"phonefprint/scripts/format"
)

const sha256Size = 32

// pingInterval is how often the sim sends a ping. The daemon drops links
// silent for ~30s, so pinging twice that fast keeps the link healthy.
const pingInterval = 15 * time.Second

func main() {
	addr := flag.String("addr", "127.0.0.1:4443", "daemon TLS listener host:port")
	fpHex := flag.String("fp", "", "lowercase hex SHA-256 of the server certificate DER (required; the daemon logs it at startup)")
	keyB64 := flag.String("key", "", "base64 (standard, padded) Ed25519 private key")
	decision := flag.String("decision", "approve", "decision to send: approve, deny, or hold (never answer)")
	once := flag.Bool("once", false, "handle one pending request, then exit")
	keygen := flag.Bool("keygen", false, "print a fresh \"<priv_b64> <pub_b64>\" pair and exit")
	flag.Parse()

	if *keygen {
		pub, priv, err := format.GenerateKey()
		if err != nil {
			log.Fatalf("phone-sim: keygen: %v", err)
		}
		fmt.Printf("%s %s\n", base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub))
		return
	}

	if *keyB64 == "" {
		log.Fatal("phone-sim: -key is required")
	}
	priv, err := decodePriv(*keyB64)
	if err != nil {
		log.Fatalf("phone-sim: %v", err)
	}
	if *decision != "approve" && *decision != "deny" && *decision != "hold" {
		log.Fatalf("phone-sim: -decision must be approve, deny or hold, got %q", *decision)
	}
	fp, err := decodeFP(*fpHex)
	if err != nil {
		log.Fatalf("phone-sim: %v", err)
	}

	hello, err := json.Marshal(helloFrame{
		Type:   "hello",
		PubKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		Name:   "phone-sim",
	})
	if err != nil {
		log.Fatalf("phone-sim: %v", err)
	}

	for {
		conn, err := dialTLS(*addr, fp)
		if err != nil {
			var fpErr *fingerprintMismatchError
			if errors.As(err, &fpErr) {
				log.Fatalf("phone-sim: %v", err)
			}
			log.Printf("phone-sim: dial %s failed: %v (retrying in 2s)", *addr, err)
			time.Sleep(2 * time.Second)
			continue
		}
		link := &simLink{conn: conn}
		if err := link.write(hello); err != nil {
			log.Printf("phone-sim: hello write failed: %v", err)
			_ = conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("phone-sim: connected to %s (decision=%s)", *addr, *decision)
		handled, linkErr := handleLink(link, *decision, priv, *once)
		_ = conn.Close()
		if *once && handled {
			log.Printf("phone-sim: handled one pending request, exiting")
			return
		}
		if linkErr != nil {
			log.Printf("phone-sim: %v", linkErr)
		}
		log.Printf("phone-sim: link closed, reconnecting in 2s")
		time.Sleep(2 * time.Second)
	}
}

// simLink bundles the TLS connection and the write mutex shared by the frame
// reader and the ping loop so concurrent frames never interleave on the wire.
type simLink struct {
	conn    net.Conn
	writeMu sync.Mutex
}

// write sends payload as one length-prefixed frame under the link's write
// mutex.
func (l *simLink) write(payload []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return writeFrame(l.conn, payload)
}

// handleLink reads frames from the daemon until the link closes or a write
// fails, with a ping loop keeping the daemon's idle timer reset. Every
// pending frame is signed and answered with a decision frame (unless
// -decision=hold, or -once and one pending is already being answered);
// decision-result frames are logged — and in -once mode receiving the result
// for the answered pending ends the link. It reports whether at least one
// pending request was handled.
func handleLink(link *simLink, decision string, priv ed25519.PrivateKey, once bool) (bool, error) {
	handled := false
	pendingID := ""
	done := make(chan struct{})
	defer close(done)
	go pingLoop(link, done)

	for {
		payload, err := readFrame(link.conn)
		if err != nil {
			return handled, err
		}
		var typ struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(payload, &typ); err != nil {
			log.Printf("phone-sim: ignoring malformed frame: %v", err)
			continue
		}
		switch typ.Type {
		case "welcome":
			var w welcomeFrame
			if err := json.Unmarshal(payload, &w); err != nil {
				log.Printf("phone-sim: ignoring malformed welcome: %v", err)
				continue
			}
			log.Printf("phone-sim: welcome registered=%t key=%q pending=%d", w.Registered, w.Key, len(w.Pending))
		case "registered":
			var r registeredFrame
			if err := json.Unmarshal(payload, &r); err != nil {
				log.Printf("phone-sim: ignoring malformed registered: %v", err)
				continue
			}
			log.Printf("phone-sim: registered key=%q", r.Key)
		case "pending":
			var p pendingFrame
			if err := json.Unmarshal(payload, &p); err != nil {
				log.Printf("phone-sim: ignoring malformed pending: %v", err)
				continue
			}
			handled = true
			log.Printf("phone-sim: pending id=%s user=%q service=%q tty=%q expires_at=%d",
				p.ID, p.User, p.Service, p.TTY, p.ExpiresAt)
			if decision == "hold" {
				log.Printf("phone-sim: session %s: holding (decision=hold)", p.ID)
				continue
			}
			if once && pendingID != "" {
				log.Printf("phone-sim: session %s: ignoring (already answering %s)", p.ID, pendingID)
				continue
			}
			if err := answerPending(link, p, decision, priv); err != nil {
				return handled, err
			}
			pendingID = p.ID
		case "decision-result":
			var res decisionResultFrame
			if err := json.Unmarshal(payload, &res); err != nil {
				log.Printf("phone-sim: ignoring malformed decision-result: %v", err)
				continue
			}
			if res.Error != "" {
				log.Printf("phone-sim: decision-result id=%s error=%s", res.ID, res.Error)
			} else {
				log.Printf("phone-sim: decision-result id=%s status=%s key=%q", res.ID, res.Status, res.Key)
			}
			if once && pendingID != "" && res.ID == pendingID {
				return handled, nil
			}
		case "pong":
			// Heartbeat answer; nothing to do.
		default:
			log.Printf("phone-sim: ignoring frame type %q", typ.Type)
		}
	}
}

// pingLoop sends a ping frame every pingInterval until done is closed, so a
// link with nothing to say still resets the daemon's idle timer.
func pingLoop(link *simLink, done <-chan struct{}) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			b, err := json.Marshal(pingFrame{Type: "ping"})
			if err != nil {
				continue
			}
			if link.write(b) != nil {
				return
			}
		}
	}
}

// answerPending signs the pinned message for one pending frame and writes the
// decision frame back.
func answerPending(link *simLink, p pendingFrame, decision string, priv ed25519.PrivateKey) error {
	nonce, err := base64.StdEncoding.DecodeString(p.Nonce)
	if err != nil || len(nonce) != 32 {
		return fmt.Errorf("session %s: bad nonce in pending frame", p.ID)
	}

	msg := format.SignedMessage(decision, p.User, p.Service, p.TTY, nonce)
	sig := ed25519.Sign(priv, msg)
	out, err := json.Marshal(decisionFrame{
		Type:     "decision",
		ID:       p.ID,
		Decision: decision,
		Sig:      base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if err := link.write(out); err != nil {
		return fmt.Errorf("session %s: decision write failed: %v", p.ID, err)
	}
	log.Printf("phone-sim: session %s user=%q service=%q tty=%q: sent %s",
		p.ID, p.User, p.Service, p.TTY, decision)
	return nil
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

// decodeFP parses -fp into the 32-byte pinned fingerprint. It is required:
// without a pin the sim refuses to run rather than talk to an unverified
// server.
func decodeFP(s string) ([32]byte, error) {
	var fp [32]byte
	if s == "" {
		return fp, errors.New("-fp is required: the lowercase hex SHA-256 of the server certificate DER (daemon logs it at startup)")
	}
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != sha256Size {
		return fp, errors.New("invalid -fp: want 64 lowercase hex chars (SHA-256 of the certificate DER)")
	}
	copy(fp[:], raw)
	return fp, nil
}
