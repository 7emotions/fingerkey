package main

import (
	"encoding/binary"
	"errors"
	"io"
)

// maxFrameSize caps a single frame at 1 MiB, mirroring daemon/frame.go.
const maxFrameSize = 1 << 20

// errFrameTooLarge is returned by readFrame when the declared frame length
// exceeds maxFrameSize; no payload is allocated in that case.
var errFrameTooLarge = errors.New("frame too large")

// helloFrame is the sim→daemon first frame. The shape mirrors
// daemon/frame.go; name is display-only.
type helloFrame struct {
	Type   string `json:"type"`
	PubKey string `json:"pubkey"`
	Name   string `json:"name"`
}

// welcomeFrame is the daemon's answer to hello.
type welcomeFrame struct {
	Type       string         `json:"type"`
	Registered bool           `json:"registered"`
	Key        string         `json:"key,omitempty"`
	Pending    []pendingFrame `json:"pending"`
}

// registeredFrame confirms a pairing-token registration.
type registeredFrame struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// pendingFrame is the daemon→phone notification for a new pending session.
// The nonce is standard-base64 of the 32 raw bytes. The shape mirrors
// daemon/frame.go.
type pendingFrame struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Nonce     string `json:"nonce"`
	User      string `json:"user"`
	Service   string `json:"service"`
	TTY       string `json:"tty"`
	ExpiresAt int64  `json:"expires_at"`
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

// pingFrame is the keepalive the sim sends about every pingInterval.
type pingFrame struct {
	Type string `json:"type"`
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
