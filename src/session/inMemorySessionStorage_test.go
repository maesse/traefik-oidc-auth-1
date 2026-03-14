package session

import (
	"sync"
	"testing"
	"time"
)

func TestInMemoryStoreAndRetrieve(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)

	state := &SessionState{
		Id:          "test-id-1",
		AccessToken: "access-token-value",
		IdToken:     "id-token-value",
		RefreshedAt: time.Now(),
	}

	ticket, err := storage.StoreSession("test-id-1", state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	if ticket != "test-id-1" {
		t.Fatalf("Expected ticket to be the session ID, got %q", ticket)
	}

	retrieved, err := storage.TryGetSession(ticket)
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}

	if retrieved.Id != state.Id {
		t.Errorf("Expected Id %q, got %q", state.Id, retrieved.Id)
	}
	if retrieved.AccessToken != state.AccessToken {
		t.Errorf("Expected AccessToken %q, got %q", state.AccessToken, retrieved.AccessToken)
	}
	if retrieved.IdToken != state.IdToken {
		t.Errorf("Expected IdToken %q, got %q", state.IdToken, retrieved.IdToken)
	}
}

func TestInMemorySessionNotFound(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)

	_, err := storage.TryGetSession("nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent session, got nil")
	}
}

func TestInMemoryDeleteSession(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)

	state := &SessionState{
		Id:          "delete-me",
		AccessToken: "token",
	}

	_, err := storage.StoreSession("delete-me", state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	err = storage.DeleteSession("delete-me")
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	_, err = storage.TryGetSession("delete-me")
	if err == nil {
		t.Fatal("Expected error after deletion, got nil")
	}
}

func TestInMemorySessionExpiration(t *testing.T) {
	// Use a 1-second max age
	storage := CreateInMemorySessionStorage(1)

	state := &SessionState{
		Id:          "expire-me",
		AccessToken: "token",
	}

	_, err := storage.StoreSession("expire-me", state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	// Should be retrievable immediately
	_, err = storage.TryGetSession("expire-me")
	if err != nil {
		t.Fatalf("TryGetSession should succeed immediately: %v", err)
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	_, err = storage.TryGetSession("expire-me")
	if err == nil {
		t.Fatal("Expected error for expired session, got nil")
	}
}

func TestInMemorySessionUpdate(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)

	state := &SessionState{
		Id:          "update-me",
		AccessToken: "old-token",
	}

	_, err := storage.StoreSession("update-me", state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	// Update with new state
	updatedState := &SessionState{
		Id:          "update-me",
		AccessToken: "new-token",
	}

	_, err = storage.StoreSession("update-me", updatedState)
	if err != nil {
		t.Fatalf("StoreSession (update) failed: %v", err)
	}

	retrieved, err := storage.TryGetSession("update-me")
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}

	if retrieved.AccessToken != "new-token" {
		t.Errorf("Expected updated AccessToken %q, got %q", "new-token", retrieved.AccessToken)
	}
}

func TestInMemoryPassiveEviction(t *testing.T) {
	storage := CreateInMemorySessionStorage(1)

	state1 := &SessionState{Id: "evict-1", AccessToken: "t1"}
	state2 := &SessionState{Id: "evict-2", AccessToken: "t2"}

	storage.StoreSession("evict-1", state1)
	storage.StoreSession("evict-2", state2)

	// Wait for both to expire
	time.Sleep(1100 * time.Millisecond)

	// Storing a new session should evict the expired ones
	state3 := &SessionState{Id: "fresh", AccessToken: "t3"}
	storage.StoreSession("fresh", state3)

	storage.mu.RLock()
	count := len(storage.entries)
	storage.mu.RUnlock()

	if count != 1 {
		t.Errorf("Expected 1 entry after eviction, got %d", count)
	}
}

func TestInMemoryConcurrentAccess(t *testing.T) {
	storage := CreateInMemorySessionStorage(60)

	var wg sync.WaitGroup
	n := 100

	// Concurrent writes
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := GenerateSessionId()
			state := &SessionState{
				Id:          id,
				AccessToken: "token",
			}
			_, err := storage.StoreSession(id, state)
			if err != nil {
				t.Errorf("StoreSession failed: %v", err)
			}
		}(i)
	}

	wg.Wait()

	storage.mu.RLock()
	count := len(storage.entries)
	storage.mu.RUnlock()

	if count != n {
		t.Errorf("Expected %d entries, got %d", n, count)
	}
}

func TestInMemoryDefaultMaxAge(t *testing.T) {
	// maxAge <= 0 should default to 3600
	storage := CreateInMemorySessionStorage(0)
	if storage.maxAge != defaultMaxAge {
		t.Errorf("Expected default maxAge %d, got %d", defaultMaxAge, storage.maxAge)
	}

	storage2 := CreateInMemorySessionStorage(-5)
	if storage2.maxAge != defaultMaxAge {
		t.Errorf("Expected default maxAge %d, got %d", defaultMaxAge, storage2.maxAge)
	}
}
