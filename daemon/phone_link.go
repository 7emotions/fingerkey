package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// phoneLink is one connected phone stream (the BlueZ SPP socket in
// production, a net.Pipe in tests): the framed push-based approval link.
// It runs exactly two goroutines — a pusher forwarding new pending sessions
// and a reader handling inbound decision frames. All writes go through
// writeMu so frames from the two goroutines never interleave.
type phoneLink struct {
	rwc     io.ReadWriteCloser
	writeMu sync.Mutex
}

// pendingFrame is the daemon→phone notification for a new pending session.
// The nonce is standard-base64 of the 32 raw bytes. The shape is the
// cross-language contract mirrored by app/lib/frame.dart.
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

// run drives the link: it subscribes to the store and spawns the pusher and
// reader goroutines, then blocks until the link dies. It registers the link
// so phoneConnected() reflects reality for its whole lifetime. The
// subscription is taken BEFORE registering: once phoneConnected() turns true
// the pusher is already subscribed, so a session created immediately after
// the check can never be missed (no replay exists).
func (l *phoneLink) run(store *Store, keys map[string]ed25519.PublicKey) {
	ch, unsub := store.Subscribe()
	registerPhoneLink(l)
	defer unregisterPhoneLink(l)

	// done closes exactly once — when the link is finished — so the pusher
	// blocked on ch notices unsubscribe/link-close and the reader's
	// readFrame error reaches everyone. finish is idempotent via once.
	done := make(chan struct{})
	var once sync.Once
	finish := func() {
		once.Do(func() {
			unsub()
			_ = l.rwc.Close()
			close(done)
		})
	}

	go l.push(ch, done, finish)
	go l.read(store, keys, finish)

	<-done
}

// push forwards every created session to the phone as a pending frame until
// the link finishes or a write fails.
func (l *phoneLink) push(ch <-chan *Session, done <-chan struct{}, finish func()) {
	defer finish()
	for {
		select {
		case <-done:
			return
		case s := <-ch:
			payload, err := json.Marshal(pendingFrame{
				Type:    "pending",
				ID:      s.ID,
				Nonce:   base64.StdEncoding.EncodeToString(s.Nonce),
				User:    s.User,
				Service: s.Service,
				TTY:     s.TTY,
			})
			if err != nil || !l.writePayload(payload) {
				return
			}
		}
	}
}

// read consumes inbound frames: decision frames are verified and applied via
// decide and answered with a decision-result; anything else is answered with
// a bare bad-message. On a read error (EOF/closed link) or a failed write the
// link is finished and the loop exits.
func (l *phoneLink) read(store *Store, keys map[string]ed25519.PublicKey, finish func()) {
	defer finish()
	for {
		payload, err := readFrame(l.rwc)
		if err != nil {
			return
		}
		var f decisionFrame
		if err := json.Unmarshal(payload, &f); err != nil || f.Type != "decision" {
			// Unknown/other type or malformed JSON: no session id is
			// recoverable, so the answer carries an empty id.
			res, _ := json.Marshal(decisionResultFrame{Type: "decision-result", Error: "bad-message"})
			if !l.writePayload(res) {
				return
			}
			continue
		}
		code, status, key := decide(store, keys, f.ID, f.Decision, f.Sig)
		res := decisionResultFrame{Type: "decision-result", ID: f.ID}
		if code == http.StatusOK {
			res.Status = status
			res.Key = key
		} else {
			res.Error = decisionError(code)
		}
		payload, _ = json.Marshal(res)
		if !l.writePayload(payload) {
			return
		}
	}
}

// writePayload sends payload as one framed write under writeMu and reports
// whether it succeeded.
func (l *phoneLink) writePayload(payload []byte) bool {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return writeFrame(l.rwc, payload) == nil
}

// decisionError maps decide's status code to the phone-facing error reason.
// decide only ever returns 200/400/401/404/409.
func decisionError(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "bad-decision"
	case http.StatusUnauthorized:
		return "invalid-signature"
	case http.StatusNotFound:
		return "unknown-session"
	case http.StatusConflict:
		return "not-pending"
	}
	return "decision failed"
}

// registerPhoneLink bumps the active phone-link counter. The subscription is
// always taken first (see run), so phoneConnected() implies a live pusher.
func registerPhoneLink(l *phoneLink) {
	phoneLinks.Lock()
	phoneLinks.active++
	phoneLinks.Unlock()
}

// unregisterPhoneLink decrements the active phone-link counter.
func unregisterPhoneLink(l *phoneLink) {
	phoneLinks.Lock()
	phoneLinks.active--
	phoneLinks.Unlock()
}
