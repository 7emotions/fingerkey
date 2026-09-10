package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// sessionTTL is how long a pending session stays valid. It is a package var
// so tests can shorten it.
var sessionTTL = 60 * time.Second

// maxSessions bounds the store: every Create evicts expired sessions and, at
// the bound, the oldest terminal one; with no evictable terminal session
// Create is rejected. A package var so tests can shrink it.
var maxSessions = 256

// errStoreFull is returned by Create when the store is at maxSessions and no
// terminal session can be evicted.
var errStoreFull = errors.New("session store full")

// Session status values.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
)

// Session is one pending approval request.
type Session struct {
	ID        string
	Nonce     []byte
	Status    string
	User      string
	Service   string
	TTY       string
	CreatedAt time.Time
	ExpiresAt time.Time
	DecidedBy string
}

// CurrentStatus reports the effective status, mapping an expired pending
// session to "expired". Terminal sessions (approved/denied) keep their status.
func (s *Session) CurrentStatus() string {
	if s.Status == StatusPending && time.Now().After(s.ExpiresAt) {
		return StatusExpired
	}
	return s.Status
}

// Store is an in-memory session store guarded by a mutex. It pushes every
// newly created session to every subscriber registered via Subscribe (the
// push-based phone link).
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	subs     map[chan *Session]struct{}
}

// NewStore returns an empty session store.
func NewStore() *Store {
	return &Store{
		sessions: make(map[string]*Session),
		subs:     make(map[chan *Session]struct{}),
	}
}

// Create generates a new pending session with a random 128-bit id (hex
// encoded) and a random 32-byte nonce. Expired sessions are evicted first;
// at maxSessions the oldest terminal session is evicted to make room; with
// no evictable terminal session Create returns errStoreFull.
func (st *Store) Create(user, service, tty string) (*Session, error) {
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	now := time.Now()
	s := &Session{
		ID:        id,
		Nonce:     nonce,
		Status:    StatusPending,
		User:      user,
		Service:   service,
		TTY:       tty,
		CreatedAt: now,
		ExpiresAt: now.Add(sessionTTL),
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.evictExpiredLocked(now)
	if len(st.sessions) >= maxSessions {
		oldest := st.oldestTerminalLocked()
		if oldest == nil {
			return nil, errStoreFull
		}
		delete(st.sessions, oldest.ID)
	}
	st.sessions[id] = s
	for sub := range st.subs {
		select {
		case sub <- s:
		default: // subscriber buffer full: skip this delivery
		}
	}
	return s, nil
}

// evictExpiredLocked drops expired pending sessions (TTL eviction). Terminal
// sessions never expire; the maxSessions bound evicts them instead.
func (st *Store) evictExpiredLocked(now time.Time) {
	for id, s := range st.sessions {
		if s.CurrentStatus() == StatusExpired {
			delete(st.sessions, id)
		}
	}
}

// oldestTerminalLocked returns the terminal (approved/denied) session with
// the earliest CreatedAt, or nil if none exists.
func (st *Store) oldestTerminalLocked() *Session {
	var oldest *Session
	for _, s := range st.sessions {
		if s.Status == StatusPending {
			continue
		}
		if oldest == nil || s.CreatedAt.Before(oldest.CreatedAt) {
			oldest = s
		}
	}
	return oldest
}

// Subscribe registers a broadcast subscriber: every Create delivers the new
// session to the returned channel. The channel is buffered (one slot) and is
// never closed; if a Create arrives while the buffer is full, that delivery
// is skipped. The returned closure unsubscribes and is safe to call more than
// once.
func (st *Store) Subscribe() (<-chan *Session, func()) {
	st.mu.Lock()
	defer st.mu.Unlock()
	ch := make(chan *Session, 1)
	st.subs[ch] = struct{}{}
	var once sync.Once
	unsub := func() {
		once.Do(func() {
			st.mu.Lock()
			delete(st.subs, ch)
			st.mu.Unlock()
		})
	}
	return ch, unsub
}

// Pending returns every non-expired pending session, oldest first.
func (st *Store) Pending() []*Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	pending := make([]*Session, 0)
	for _, s := range st.sessions {
		if s.CurrentStatus() == StatusPending {
			pending = append(pending, s)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	return pending
}

// Get returns the session with the given id, if known.
func (st *Store) Get(id string) (*Session, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.sessions[id]
	return s, ok
}

// Approve transitions a pending session to approved, once only. It returns
// (approved, found): found is false for unknown ids; approved is false when
// the session is no longer pending (already approved, denied, or expired) and
// no state change is made.
func (st *Store) Approve(id string) (approved, found bool) {
	ok, found := st.Decide(id, StatusApproved, "")
	return ok, found
}

// Decide transitions a pending session to the given terminal status
// (StatusApproved or StatusDenied), once only, recording the deciding key's
// name in DecidedBy. It returns (ok, found): found is false for unknown ids;
// ok is false when the session is no longer pending (already decided or
// expired) and no state change is made.
func (st *Store) Decide(id, status, decidedBy string) (ok, found bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, present := st.sessions[id]
	if !present {
		return false, false
	}
	if s.CurrentStatus() != StatusPending {
		return false, true
	}
	s.Status = status
	s.DecidedBy = decidedBy
	return true, true
}

// randomHex returns the hex encoding of n crypto/rand bytes.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
