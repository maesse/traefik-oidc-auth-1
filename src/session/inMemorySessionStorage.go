package session

import (
	"fmt"
	"sync"
	"time"
)

const defaultMaxAge = 3600 // 1 hour

type sessionEntry struct {
	state     *SessionState
	expiresAt time.Time
}

type InMemorySessionStorage struct {
	mu      sync.RWMutex
	entries map[string]*sessionEntry
	maxAge  int // seconds
}

func CreateInMemorySessionStorage(maxAge int) *InMemorySessionStorage {
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}

	return &InMemorySessionStorage{
		entries: make(map[string]*sessionEntry),
		maxAge:  maxAge,
	}
}

func (storage *InMemorySessionStorage) StoreSession(sessionId string, state *SessionState) (string, error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()

	// Passive eviction: clean up expired entries on each store
	storage.evictExpiredLocked()

	storage.entries[sessionId] = &sessionEntry{
		state:     state,
		expiresAt: time.Now().Add(time.Duration(storage.maxAge) * time.Second),
	}

	// Return only the session ID as the ticket (not the full JSON).
	// The caller will encrypt this before putting it in the cookie.
	return sessionId, nil
}

func (storage *InMemorySessionStorage) TryGetSession(sessionTicket string) (*SessionState, error) {
	storage.mu.RLock()
	defer storage.mu.RUnlock()

	entry, ok := storage.entries[sessionTicket]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", sessionTicket)
	}

	if time.Now().After(entry.expiresAt) {
		return nil, fmt.Errorf("session expired: %s", sessionTicket)
	}

	return entry.state, nil
}

func (storage *InMemorySessionStorage) DeleteSession(sessionId string) error {
	storage.mu.Lock()
	defer storage.mu.Unlock()

	delete(storage.entries, sessionId)
	return nil
}

// evictExpiredLocked removes all expired entries. Must be called with mu held.
func (storage *InMemorySessionStorage) evictExpiredLocked() {
	now := time.Now()
	for id, entry := range storage.entries {
		if now.After(entry.expiresAt) {
			delete(storage.entries, id)
		}
	}
}
