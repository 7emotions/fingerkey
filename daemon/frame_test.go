package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"runtime"
	"testing"
)

// oneByteReader caps every Read at a single byte, so a caller that issues
// large Reads still observes the underlying stream one byte at a time.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

// fakeHeaderReader yields a 4-byte big-endian 2 MiB length prefix forever
// without advancing. It is stateless, so readFrame can be run against it
// repeatedly to measure allocations.
type fakeHeaderReader struct{}

func (fakeHeaderReader) Read(p []byte) (int, error) {
	binary.BigEndian.PutUint32(p[:4], 2<<20)
	return 4, nil
}

// framePayload returns n deterministic pseudo-random bytes.
func framePayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i * 37)
	}
	return p
}

// TestFrameRoundTrip writes a 200-byte payload through writeFrame and reads
// it back with readFrame over a net.Pipe; the result must be byte-identical.
func TestFrameRoundTrip(t *testing.T) {
	payload := framePayload(200)

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	writeErr := make(chan error, 1)
	go func() { writeErr <- writeFrame(c, payload) }()

	got, err := readFrame(s)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch:\n got %v\nwant %v", got, payload)
	}
}

// TestFrameReadPartialReads reads a frame back through a 1-byte-at-a-time
// reader, forcing readFrame to reassemble the 4-byte header and the 200-byte
// payload from 204 separate single-byte reads.
func TestFrameReadPartialReads(t *testing.T) {
	payload := framePayload(200)

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	writeErr := make(chan error, 1)
	go func() { writeErr <- writeFrame(c, payload) }()

	got, err := readFrame(oneByteReader{s})
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch:\n got %v\nwant %v", got, payload)
	}
}

// TestFrameTooLarge writes a fake 2 MiB length prefix (no payload) and
// asserts readFrame returns errFrameTooLarge with a nil payload: the header
// is refused before any payload allocation happens.
func TestFrameTooLarge(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 2<<20) // over maxFrameSize
	writeErr := make(chan error, 1)
	go func() { _, err := c.Write(hdr); writeErr <- err }()

	got, err := readFrame(s)
	if err != errFrameTooLarge {
		t.Fatalf("readFrame err = %v, want errFrameTooLarge", err)
	}
	if got != nil {
		t.Fatalf("readFrame returned %d payload bytes, want nil (no allocation)", len(got))
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write header: %v", err)
	}

	// The oversized path must refuse the frame before allocating its
	// payload: 1000 fake 2 MiB headers must not move anything close to
	// 1000×2 MiB through the allocator. (The few bytes for the 4-byte
	// header itself are irrelevant; a payload allocation is not.)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 1000; i++ {
		if _, err := readFrame(fakeHeaderReader{}); err != errFrameTooLarge {
			t.Fatalf("readFrame err = %v, want errFrameTooLarge", err)
		}
	}
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 1<<20 {
		t.Fatalf("readFrame moved %d bytes through the allocator for 1000 oversized headers, want < 1 MiB (payload must not be allocated)", alloc)
	}
}

// ---- v2 business-frame codec tests ----

// roundTripCodec marshals in to JSON, walks it through writeFrame/readFrame
// over a net.Pipe and unmarshals it into out (a pointer to the same type as
// in), failing the test on any error.
func roundTripCodec(t *testing.T, in interface{}, out interface{}) {
	t.Helper()
	payload, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	writeErr := make(chan error, 1)
	go func() { writeErr <- writeFrame(c, payload) }()
	got, err := readFrame(s)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if err := json.Unmarshal(got, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// TestBusinessFrameCodec pins the six v2 business frames through a
// marshal → wire → unmarshal round trip.
func TestBusinessFrameCodec(t *testing.T) {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	t.Run("hello", func(t *testing.T) {
		in := helloFrame{Type: "hello", PubKey: "cHVibGljLWtleQ==", Name: "pixel-8", Token: "tok"}
		var out helloFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("welcome", func(t *testing.T) {
		in := welcomeFrame{
			Type:       "welcome",
			Registered: true,
			Key:        "alice",
			Pending: []pendingFrame{{
				Type:      "pending",
				ID:        "abc",
				Nonce:     "bm9uY2U=",
				User:      "alice",
				Service:   "sudo",
				TTY:       "/dev/pts/0",
				ExpiresAt: 1780000000,
			}},
		}
		var out welcomeFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("welcome-unregistered", func(t *testing.T) {
		payload, err := json.Marshal(welcomeFrame{Type: "welcome", Registered: false, Pending: []pendingFrame{}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Contains(payload, []byte(`"registered":false`)) {
			t.Errorf("payload = %s, want explicit registered:false", payload)
		}
		if !bytes.Contains(payload, []byte(`"pending":[]`)) {
			t.Errorf("payload = %s, want explicit empty pending array", payload)
		}
	})

	t.Run("registered", func(t *testing.T) {
		in := registeredFrame{Type: "registered", Key: "pixel-8"}
		var out registeredFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("pending", func(t *testing.T) {
		in := pendingFrame{Type: "pending", ID: "abc", Nonce: "bm9uY2U=", User: "alice", Service: "sudo", TTY: "/dev/pts/0", ExpiresAt: 1780000000}
		var out pendingFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("decision", func(t *testing.T) {
		in := decisionFrame{Type: "decision", ID: "abc", Decision: "approve", Sig: "c2ln"}
		var out decisionFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("decision-result-success", func(t *testing.T) {
		in := decisionResultFrame{Type: "decision-result", ID: "abc", Status: "approved", Key: "alice"}
		var out decisionResultFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("decision-result-error", func(t *testing.T) {
		in := decisionResultFrame{Type: "decision-result", ID: "abc", Error: "unpaired-key"}
		var out decisionResultFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("ping", func(t *testing.T) {
		in := pingFrame{Type: "ping"}
		var out pingFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})

	t.Run("pong", func(t *testing.T) {
		in := pongFrame{Type: "pong"}
		var out pongFrame
		roundTripCodec(t, in, &out)
		if !reflect.DeepEqual(in, out) {
			t.Errorf("round trip = %+v, want %+v", out, in)
		}
	})
}
