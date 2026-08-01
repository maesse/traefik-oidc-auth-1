package session

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

func inMemorySessionStorageTestDependencies() (*logging.Logger, *config.Config) {
	return logging.CreateLogger(logging.LevelError), &config.Config{}
}

func TestInMemorySessionStorageRoundTrip(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)
	logger, cfg := inMemorySessionStorageTestDependencies()
	state := &SessionState{
		Id:             "9a8799f4-f9f5-4e45-8da8-f54c17547ac2",
		AccessToken:    "access-token",
		RefreshToken:   "refresh-token",
		IsAuthorized:   true,
		TokenExpiresIn: 3600,
	}

	ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}
	if ticket != state.Id {
		t.Fatalf("ticket = %q, want session id %q", ticket, state.Id)
	}

	actual, err := storage.TryGetSession(logger, cfg, ticket)
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}
	if *actual != *state {
		t.Fatalf("round trip changed session state: got %#v, want %#v", actual, state)
	}
}

func TestInMemorySessionStorageCopiesState(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)
	logger, cfg := inMemorySessionStorageTestDependencies()
	state := &SessionState{
		Id:          "8c379c4d-dba7-4642-8575-4fc1d61f6a7b",
		AccessToken: "original",
	}
	if _, err := storage.StoreSession(logger, cfg, state.Id, state); err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	state.AccessToken = "changed after store"
	retrieved, err := storage.TryGetSession(logger, cfg, state.Id)
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}
	if retrieved.AccessToken != "original" {
		t.Fatalf("stored state was mutated through the caller: %q", retrieved.AccessToken)
	}

	retrieved.AccessToken = "changed after load"
	retrievedAgain, err := storage.TryGetSession(logger, cfg, state.Id)
	if err != nil {
		t.Fatalf("second TryGetSession failed: %v", err)
	}
	if retrievedAgain.AccessToken != "original" {
		t.Fatalf("stored state was mutated through a loaded value: %q", retrievedAgain.AccessToken)
	}
}

func TestInMemorySessionStorageExpiration(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)
	logger, cfg := inMemorySessionStorageTestDependencies()
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	storage.now = func() time.Time { return now }
	state := &SessionState{Id: "9d89ef4a-556d-4939-89fc-af160b1f9f77"}
	if _, err := storage.StoreSession(logger, cfg, state.Id, state); err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	now = now.Add(60 * time.Second)
	_, err := storage.TryGetSession(logger, cfg, state.Id)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("TryGetSession error = %v, want ErrSessionNotFound", err)
	}
	if len(storage.entries) != 0 {
		t.Fatalf("expired entry was not removed: got %d entries", len(storage.entries))
	}
}

func TestInMemorySessionStorageDelete(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)
	logger, cfg := inMemorySessionStorageTestDependencies()
	state := &SessionState{Id: "c3850325-90de-429d-bb20-a2586c426365"}
	if _, err := storage.StoreSession(logger, cfg, state.Id, state); err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}
	if err := storage.DeleteSession(logger, cfg, state.Id); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	if _, err := storage.TryGetSession(logger, cfg, state.Id); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("TryGetSession error = %v, want ErrSessionNotFound", err)
	}
}

func TestInMemorySessionStorageRejectsCookieStorageTicket(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)
	logger, cfg := inMemorySessionStorageTestDependencies()
	_, err := storage.TryGetSession(logger, cfg, "an-encrypted-cookie-storage-ticket")
	if !errors.Is(err, ErrInvalidSessionTicket) {
		t.Fatalf("TryGetSession error = %v, want ErrInvalidSessionTicket", err)
	}
}

func TestInMemorySessionStorageConcurrentAccess(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)
	logger, cfg := inMemorySessionStorageTestDependencies()
	const workers = 50
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state := &SessionState{Id: GenerateSessionId()}
			ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
			if err != nil {
				t.Errorf("StoreSession failed: %v", err)
				return
			}
			if _, err := storage.TryGetSession(logger, cfg, ticket); err != nil {
				t.Errorf("TryGetSession failed: %v", err)
			}
		}()
	}

	wg.Wait()
	if len(storage.entries) != workers {
		t.Fatalf("stored entries = %d, want %d", len(storage.entries), workers)
	}
}
