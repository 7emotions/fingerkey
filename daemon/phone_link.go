package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// connID identifies one accepted phone connection in the link registry.
type connID uint64

// Link lifecycle timeouts, package vars so tests can shorten them:
// helloTimeout bounds the time between the (TLS) handshake completing and the
// first frame arriving (which must be a hello); linkIdleTimeout closes a link
// that receives no frame at all — the phone keeps its link healthy by sending
// ping every ~15s, and every received frame resets the timer.
var (
	helloTimeout    = 5 * time.Second
	linkIdleTimeout = 30 * time.Second
)

// queueDepth bounds a link's outbound push queue. Only pending pushes are
// dropped when the queue is full (audited as push-dropped); control frames
// (welcome, registered) are written directly and never enter the queue.
const queueDepth = 8

// phoneLink is one connected phone stream (a TLS TCP socket in production,
// a net.Pipe in tests): the framed push-based approval link. It runs exactly
// three goroutines after the hello handshake — a pusher forwarding new
// pending sessions, a writer draining the outbound queue, and a reader
// handling inbound frames. All writes go through writeMu so frames never
// interleave.
type phoneLink struct {
	rwc        io.ReadWriteCloser
	writeMu    sync.Mutex
	registered bool        // set once hello's pubkey matched a paired key
	queue      chan []byte // outbound pending pushes, bounded
}

// newPhoneLink builds a phoneLink around a connected stream.
func newPhoneLink(rwc io.ReadWriteCloser) *phoneLink {
	return &phoneLink{rwc: rwc, queue: make(chan []byte, queueDepth)}
}

// startPhoneLink wraps an accepted stream (a TLS socket in production, a
// sim-socket or net.Pipe conn in tests) in a phoneLink and starts its run
// loop.
func startPhoneLink(rwc io.ReadWriteCloser, store *Store, keys *keyProvider) {
	if c, ok := rwc.(net.Conn); ok {
		enableKeepAlive(c)
	}
	go newPhoneLink(rwc).run(store, keys)
}

// run drives the link lifecycle: it registers the link, gates it on a hello
// frame, and — for registered links only — subscribes to the store, sends the
// welcome control frame synchronously (direct write, before any push), and
// then runs the push/write/read goroutines until the link dies.
func (l *phoneLink) run(store *Store, keys *keyProvider) {
	id := registerPhoneLink(l)
	defer unregisterPhoneLink(id)

	done := make(chan struct{})
	var once sync.Once
	finish := func() {
		once.Do(func() {
			_ = l.rwc.Close()
			close(done)
		})
	}
	defer finish()

	// The handshake gate: the first frame must be a well-formed hello within
	// helloTimeout. Anything else — or nothing — is refused before the link
	// can consume store resources.
	setReadDeadline(l.rwc, time.Now().Add(helloTimeout))
	payload, err := readFrame(l.rwc)
	if err != nil {
		return
	}
	var hello helloFrame
	keyName := ""
	registered := false
	if err := json.Unmarshal(payload, &hello); err == nil && hello.Type == "hello" {
		if pub, perr := decodePubKey(hello.PubKey); perr == nil {
			keyName, registered = keys.Lookup(pub)
		}
	}
	if !registered {
		// Unregistered pubkey (or no valid hello): answer welcome{registered:false}
		// and close. No subscription, no pushes, no decision-results.
		_ = l.writePayload(frameJSON(welcomeFrame{Type: "welcome", Registered: false, Pending: []pendingFrame{}}))
		return
	}

	// Registered: subscribe BEFORE snapshotting Pending() so no session can
	// slip between the two; the welcome control frame is written directly so
	// it always precedes the first push and is never dropped. Duplicates
	// across the snapshot and the live subscription are the phone's to dedup.
	ch, unsub := store.Subscribe()
	defer unsub()
	l.registered = true
	if !l.writePayload(frameJSON(welcomeFrame{
		Type:       "welcome",
		Registered: true,
		Key:        keyName,
		Pending:    pendingFrames(store.Pending()),
	})) {
		return
	}

	go l.push(ch, done, finish)
	go l.writeLoop(done, finish)
	l.read(store, keys, finish)
}

// push forwards every created session to the phone's outbound queue until the
// link finishes. When the queue is full the pending push is dropped — never
// silently — with a push-dropped audit line.
func (l *phoneLink) push(ch <-chan *Session, done <-chan struct{}, finish func()) {
	defer finish()
	for {
		select {
		case <-done:
			return
		case s := <-ch:
			select {
			case l.queue <- frameJSON(pendingFrameFromSession(s)):
			case <-done:
				return
			default:
				audit("push-dropped", "id", s.ID, "user", s.User, "service", s.Service, "tty", s.TTY)
			}
		}
	}
}

// writeLoop drains the outbound queue onto the wire until the link finishes
// or a write fails.
func (l *phoneLink) writeLoop(done <-chan struct{}, finish func()) {
	defer finish()
	for {
		select {
		case <-done:
			return
		case payload := <-l.queue:
			if !l.writePayload(payload) {
				return
			}
		}
	}
}

// read consumes inbound frames under the idle timer: every frame resets the
// deadline, so a silent healthy link dies after linkIdleTimeout while a
// pinging one lives. On a read error (EOF/closed link/timeout) the link is
// finished and the loop exits.
func (l *phoneLink) read(store *Store, keys *keyProvider, finish func()) {
	defer finish()
	for {
		setReadDeadline(l.rwc, time.Now().Add(linkIdleTimeout))
		payload, err := readFrame(l.rwc)
		if err != nil {
			return
		}
		if !l.dispatch(store, keys, payload) {
			return
		}
	}
}

// dispatch handles one inbound frame and reports whether the link should keep
// reading. ping is answered with pong; decision frames are verified, applied
// and their result broadcast to every registered link (only 200 outcomes
// broadcast — failures answer the requester alone); anything else is a
// bad-message.
func (l *phoneLink) dispatch(store *Store, keys *keyProvider, payload []byte) bool {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &head); err != nil {
		return l.writePayload(frameJSON(decisionResultFrame{Type: "decision-result", Error: "bad-message"}))
	}
	switch head.Type {
	case "ping":
		return l.writePayload(frameJSON(pongFrame{Type: "pong"}))
	case "decision":
		var f decisionFrame
		if err := json.Unmarshal(payload, &f); err != nil {
			return l.writePayload(frameJSON(decisionResultFrame{Type: "decision-result", Error: "bad-message"}))
		}
		code, status, key := decide(store, keys, f.ID, f.Decision, f.Sig)
		res := decisionResultFrame{Type: "decision-result", ID: f.ID}
		if code == http.StatusOK {
			res.Status = status
			res.Key = key
		} else {
			res.Error = decisionError(code)
		}
		out := frameJSON(res)
		if code != http.StatusOK {
			return l.writePayload(out)
		}
		broadcastDecisionResult(out)
		return true
	default:
		return l.writePayload(frameJSON(decisionResultFrame{Type: "decision-result", Error: "bad-message"}))
	}
}

// broadcastDecisionResult enqueues a successful decision outcome to every
// registered link (the decider included). Unregistered links never see it.
func broadcastDecisionResult(payload []byte) {
	phoneLinks.Lock()
	targets := make([]*phoneLink, 0, len(phoneLinks.links))
	for _, l := range phoneLinks.links {
		if l.registered {
			targets = append(targets, l)
		}
	}
	phoneLinks.Unlock()
	for _, l := range targets {
		select {
		case l.queue <- payload:
		default:
			audit("push-dropped", "frame", "decision-result")
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
// decide only ever returns 200/400/401/404.
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

// setReadDeadline sets the read deadline on streams that support one (TCP,
// unix sockets, net.Pipe all do).
func setReadDeadline(rwc io.ReadWriteCloser, t time.Time) {
	if c, ok := rwc.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = c.SetReadDeadline(t)
	}
}

// enableKeepAlive turns on TCP keepalive so a dead peer is eventually noticed
// even without an application-level frame exchange. No-op on non-TCP conns.
func enableKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
}

// registerPhoneLink adds the link to the registry and returns its connID.
func registerPhoneLink(l *phoneLink) connID {
	phoneLinks.Lock()
	defer phoneLinks.Unlock()
	phoneLinks.next++
	id := phoneLinks.next
	phoneLinks.links[id] = l
	return id
}

// unregisterPhoneLink removes the link from the registry.
func unregisterPhoneLink(id connID) {
	phoneLinks.Lock()
	delete(phoneLinks.links, id)
	phoneLinks.Unlock()
}
