// Command phone-sim is the phone simulator for phone-fprint-auth. It dials
// the daemon's test phone-link unix socket (-phone-sim-socket) and speaks the
// same framed protocol as the production phone (SPP): the daemon pushes
// pending frames, the sim builds the pinned signed message with the session's
// nonce, signs it with the given Ed25519 private key, and answers with a
// decision frame. It keeps listening after every answer unless -once.
//
// Usage:
//
//	phone-sim -socket <path> -key <priv_b64> [-decision approve|deny] [-once]
//
// <priv_b64> is the standard, padded base64 encoding of a 64-byte Ed25519
// private key; -decision defaults to "approve".
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"phonefprint/scripts/format"
)

// maxFrameSize caps a single frame at 1 MiB, mirroring daemon/frame.go.
const maxFrameSize = 1 << 20

// errFrameTooLarge is returned by readFrame when the declared frame length
// exceeds maxFrameSize; no payload is allocated in that case.
var errFrameTooLarge = errors.New("frame too large")

func main() {
	socket := flag.String("socket", "", "unix socket path the daemon's -phone-sim-socket listens on")
	keyB64 := flag.String("key", "", "base64 (standard, padded) Ed25519 private key")
	decision := flag.String("decision", "approve", "decision to send: approve or deny")
	once := flag.Bool("once", false, "handle one pending request, then exit")
	flag.Parse()

	if *socket == "" {
		log.Fatal("phone-sim: -socket is required")
	}
	if *keyB64 == "" {
		log.Fatal("phone-sim: -key is required")
	}
	priv, err := decodePriv(*keyB64)
	if err != nil {
		log.Fatalf("phone-sim: %v", err)
	}
	if *decision != "approve" && *decision != "deny" {
		log.Fatalf("phone-sim: -decision must be approve or deny, got %q", *decision)
	}

	for {
		conn, err := net.Dial("unix", *socket)
		if err != nil {
			log.Printf("phone-sim: dial %s failed: %v (retrying in 2s)", *socket, err)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("phone-sim: connected to %s (decision=%s)", *socket, *decision)
		handled, linkErr := handleLink(conn, *decision, priv)
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

// handleLink reads frames from the daemon until the link closes or a write
// fails. Every pending frame is signed and answered with a decision frame;
// decision-result frames are logged; anything else is ignored. It reports
// whether at least one pending request was handled.
func handleLink(conn net.Conn, decision string, priv ed25519.PrivateKey) (bool, error) {
	handled := false
	for {
		payload, err := readFrame(conn)
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
		case "pending":
			handled = true
			if err := answerPending(conn, payload, decision, priv); err != nil {
				return handled, err
			}
		case "decision-result":
			var res decisionResultFrame
			if err := json.Unmarshal(payload, &res); err != nil {
				log.Printf("phone-sim: ignoring malformed decision-result: %v", err)
				continue
			}
			if res.Error != "" {
				log.Printf("phone-sim: decision %q rejected: %s", res.ID, res.Error)
			} else {
				log.Printf("phone-sim: decision %q accepted: status=%s key=%q", res.ID, res.Status, res.Key)
			}
		default:
			log.Printf("phone-sim: ignoring frame type %q", typ.Type)
		}
	}
}

// answerPending parses one pending frame, signs the pinned message with the
// pending nonce, and writes the decision frame back.
func answerPending(conn net.Conn, payload []byte, decision string, priv ed25519.PrivateKey) error {
	var p pendingFrame
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("cannot decode pending frame: %v", err)
	}
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
	if err := writeFrame(conn, out); err != nil {
		return fmt.Errorf("session %s: decision write failed: %v", p.ID, err)
	}
	log.Printf("session %s user=%q service=%q tty=%q: sent %s",
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

// pendingFrame is the daemon→phone notification for a new pending session.
// The nonce is standard-base64 of the 32 raw bytes. The shape mirrors
// daemon/phone_link.go.
type pendingFrame struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Nonce   string `json:"nonce"`
	User    string `json:"user"`
	Service string `json:"service"`
	TTY     string `json:"tty"`
}

// decisionFrame is the phone→daemon frame: a signed approve/deny.
type decisionFrame struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Sig      string `json:"sig"`
}

// decisionResultFrame is the daemon→phone answer to a decision.
type decisionResultFrame struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Status string `json:"status,omitempty"`
	Key    string `json:"key,omitempty"`
	Error  string `json:"error,omitempty"`
}

// readFrame reads one length-prefixed frame from r: a 4-byte big-endian
// uint32 length followed by exactly that many payload bytes. If the declared
// length exceeds maxFrameSize it returns errFrameTooLarge without allocating
// the payload. It mirrors daemon/frame.go.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return nil, errFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// writeFrame writes payload to w as one length-prefixed frame: the 4-byte
// big-endian uint32 length followed by the payload bytes.
func writeFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
