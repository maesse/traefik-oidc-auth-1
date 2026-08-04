package session

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

const defaultServerSideSessionMaxAge = 3600

var (
	ErrInvalidSessionTicket = errors.New("invalid session ticket")
	ErrSessionNotFound      = errors.New("session not found")
)

type inMemorySessionEntry struct {
	state     SessionState
	expiresAt time.Time
}

type InMemorySessionStorage struct {
	mu      sync.RWMutex
	entries map[string]inMemorySessionEntry
	maxAge  time.Duration
	now     func() time.Time
}

func CreateInMemorySessionStorage(maxAgeSeconds int) *InMemorySessionStorage {
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = defaultServerSideSessionMaxAge
	}

	return &InMemorySessionStorage{
		entries: make(map[string]inMemorySessionEntry),
		maxAge:  time.Duration(maxAgeSeconds) * time.Second,
		now:     time.Now,
	}
}

func (storage *InMemorySessionStorage) StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error) {
	if state == nil || sessionId == "" {
		return "", errors.New("session state has no id")
	}
	if _, err := uuid.Parse(sessionId); err != nil {
		return "", fmt.Errorf("session state has an invalid id: %w", err)
	}

	now := storage.now()
	storage.mu.Lock()
	defer storage.mu.Unlock()

	storage.evictExpiredLocked(now)
	storage.entries[sessionId] = inMemorySessionEntry{
		state:     cloneSessionState(state),
		expiresAt: now.Add(storage.maxAge),
	}

	return sessionId, nil
}

func (storage *InMemorySessionStorage) TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error) {
	if _, err := uuid.Parse(sessionTicket); err != nil {
		return nil, fmt.Errorf("%w: expected a session id", ErrInvalidSessionTicket)
	}

	now := storage.now()
	storage.mu.RLock()
	entry, ok := storage.entries[sessionTicket]
	storage.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, sessionTicket)
	}
	if !now.Before(entry.expiresAt) {
		storage.mu.Lock()
		current, exists := storage.entries[sessionTicket]
		if exists && now.Before(current.expiresAt) {
			state := cloneSessionState(&current.state)
			storage.mu.Unlock()
			return &state, nil
		}
		if exists {
			delete(storage.entries, sessionTicket)
		}
		storage.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, sessionTicket)
	}

	state := cloneSessionState(&entry.state)
	return &state, nil
}

func cloneSessionState(state *SessionState) SessionState {
	cloned := *state
	if state.AuthorizationResults != nil {
		cloned.AuthorizationResults = make(map[string]bool, len(state.AuthorizationResults))
		for key, value := range state.AuthorizationResults {
			cloned.AuthorizationResults[key] = value
		}
	}
	return cloned
}

func (storage *InMemorySessionStorage) DeleteSession(logger *logging.Logger, config *config.Config, sessionId string) error {
	storage.mu.Lock()
	defer storage.mu.Unlock()

	delete(storage.entries, sessionId)
	return nil
}

func (storage *InMemorySessionStorage) evictExpiredLocked(now time.Time) {
	for id, entry := range storage.entries {
		if !now.Before(entry.expiresAt) {
			delete(storage.entries, id)
		}
	}
}
