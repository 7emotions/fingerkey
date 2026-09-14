package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Wire framing for the phone-facing stream: every frame is a 4-byte
// big-endian uint32 length prefix followed by exactly that many bytes of
// UTF-8 JSON. This is the cross-language framing contract mirrored by
// app/lib/frame.dart; keep the two in sync.
const maxFrameSize = 1 << 20 // 1 MiB

// errFrameTooLarge is returned by readFrame when the declared frame length
// exceeds maxFrameSize; no payload is allocated in that case.
var errFrameTooLarge = errors.New("frame too large")

// readFrame reads one length-prefixed frame from r: a 4-byte big-endian
// uint32 length followed by exactly that many payload bytes. If the declared
// length exceeds maxFrameSize it returns errFrameTooLarge without allocating
// the payload.
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

// helloFrame is the phone→daemon first frame: the phone's public key (the
// same padded base64 encoding as <name>.pub files) plus a display name. Token
// is reserved for the pairing flow (todo 6).
type helloFrame struct {
	Type   string `json:"type"`
	PubKey string `json:"pubkey"`
	Name   string `json:"name"`
	Token  string `json:"token,omitempty"`
}

// welcomeFrame is the daemon's answer to hello: whether the pubkey is paired,
// under which name, and the snapshot of currently pending sessions.
type welcomeFrame struct {
	Type       string         `json:"type"`
	Registered bool           `json:"registered"`
	Key        string         `json:"key,omitempty"`
	Pending    []pendingFrame `json:"pending"`
}

// registeredFrame confirms a pairing-token registration (sent by the todo 6
// pairing flow; the codec exists now so both sides can parse it).
type registeredFrame struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// pendingFrame is the daemon→phone notification for a new pending session.
// The nonce is standard-base64 of the 32 raw bytes. The shape is the
// cross-language contract mirrored by app/lib/frame.dart. reason and command
// are display-only context and omitted when empty.
type pendingFrame struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Nonce     string `json:"nonce"`
	User      string `json:"user"`
	Service   string `json:"service"`
	TTY       string `json:"tty"`
	Reason    string `json:"reason,omitempty"`
	Command   string `json:"command,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
}

// decisionFrame is the phone→daemon frame: a signed approve/deny.
type decisionFrame struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Sig      string `json:"sig"`
}

// decisionResultFrame is the daemon→phone answer to a decision (or to any
// unknown/malformed frame). id is deliberately NOT omitempty so a bad message
// answers with "id":"". status/key carry the outcome of a 200; error carries
// the reason otherwise.
type decisionResultFrame struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Status string `json:"status,omitempty"`
	Key    string `json:"key,omitempty"`
	Error  string `json:"error,omitempty"`
}

// pingFrame/pongFrame are the heartbeat pair: the phone sends ping about
// every 15s, the daemon answers pong; any frame either side receives resets
// that side's idle timer.
type pingFrame struct {
	Type string `json:"type"`
}

type pongFrame struct {
	Type string `json:"type"`
}

// pendingFrameFromSession renders a session as its pending frame.
func pendingFrameFromSession(s *Session) pendingFrame {
	return pendingFrame{
		Type:      "pending",
		ID:        s.ID,
		Nonce:     base64.StdEncoding.EncodeToString(s.Nonce),
		User:      s.User,
		Service:   s.Service,
		TTY:       s.TTY,
		Reason:    s.Reason,
		Command:   s.Command,
		ExpiresAt: s.ExpiresAt.Unix(),
	}
}

// pendingFrames renders the welcome snapshot, oldest first.
func pendingFrames(sessions []*Session) []pendingFrame {
	out := make([]pendingFrame, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, pendingFrameFromSession(s))
	}
	return out
}

// frameJSON marshals a frame for the wire; these structs cannot fail to
// marshal.
func frameJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// decodePubKey parses the hello pubkey: standard padded base64 of a 32-byte
// Ed25519 public key.
func decodePubKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a padded base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}
