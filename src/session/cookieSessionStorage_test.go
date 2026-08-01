package session

import (
	"strings"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

func cookieSessionStorageTestDependencies(secret string) (*logging.Logger, *config.Config) {
	return logging.CreateLogger(logging.LevelError), &config.Config{Secret: secret}
}

func TestCookieSessionStorageRoundTrip(t *testing.T) {
	storage := CreateCookieSessionStorage()
	logger, cfg := cookieSessionStorageTestDependencies("01234567890123456789012345678901")
	state := &SessionState{
		Id:                 "session-id",
		RefreshedAt:        time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC),
		AccessToken:        "access-token",
		IdToken:            "id-token",
		RefreshToken:       "refresh-token",
		IsAuthorized:       true,
		TokenExpiresIn:     3600,
		ChallengeAttempted: true,
	}

	ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}
	if ticket == "" {
		t.Fatal("StoreSession returned an empty ticket")
	}
	if strings.Contains(ticket, state.AccessToken) {
		t.Fatal("ticket contains the plaintext session state")
	}

	actual, err := storage.TryGetSession(logger, cfg, ticket)
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}
	if *actual != *state {
		t.Fatalf("round trip changed session state: got %#v, want %#v", actual, state)
	}
}

func TestCookieSessionStorageRejectsTicketEncryptedWithAnotherSecret(t *testing.T) {
	storage := CreateCookieSessionStorage()
	logger, cfg := cookieSessionStorageTestDependencies("01234567890123456789012345678901")
	ticket, err := storage.StoreSession(logger, cfg, "session-id", &SessionState{Id: "session-id"})
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	_, otherConfig := cookieSessionStorageTestDependencies("abcdefghijklmnopqrstuvwxyzABCDEF")
	_, err = storage.TryGetSession(logger, otherConfig, ticket)
	if err == nil {
		t.Fatal("TryGetSession accepted a ticket encrypted with another secret")
	}
}

func TestCookieSessionStorageDeleteIsNoOp(t *testing.T) {
	storage := CreateCookieSessionStorage()
	logger, cfg := cookieSessionStorageTestDependencies("01234567890123456789012345678901")
	if err := storage.DeleteSession(logger, cfg, "session-id"); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
}
