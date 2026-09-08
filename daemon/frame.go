package main

import (
	"encoding/binary"
	"errors"
	"io"
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
