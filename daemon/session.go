package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// sessionTTL is how long a pending session stays valid. It is a package var
// so tests can shorten it.
var sessionTTL = 60 * time.Second

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
}

// CurrentStatus reports the effective status, mapping an expired pending
// session to "expired". Terminal sessions (approved/denied) keep their status.
func (s *Session) CurrentStatus() string {
	if s.Status == StatusPending && time.Now().After(s.ExpiresAt) {
		return StatusExpired
	}
	return s.Status
}

// Store is an in-memory session store guarded by a mutex.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// NewStore returns an empty session store.
func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session)}
}

// Create generates a new pending session with a random 128-bit id (hex
// encoded) and a random 32-byte nonce.
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
	st.sessions[id] = s
	st.mu.Unlock()
	return s, nil
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
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.sessions[id]
	if !ok {
		return false, false
	}
	if s.CurrentStatus() != StatusPending {
		return false, true
	}
	s.Status = StatusApproved
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
