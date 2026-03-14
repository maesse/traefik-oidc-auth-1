package src

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func TestSessionIdpTokenExpiration(t *testing.T) {
	config := &Config{
		Provider: &ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionCookie: &SessionCookieConfig{
			MaxAge: 0,
		},
	}

	logger := logging.CreateLogger(logging.LevelDebug)

	toa := &TraefikOidcAuth{
		logger: logger,
		Config: config,
	}

	now := time.Now()

	sessionState := &session.SessionState{
		RefreshedAt:    now.Add(-29 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon := checkIdpTokenExpiresSoon(toa, sessionState)

	if expiresSoon {
		t.Fail()
	}

	sessionState = &session.SessionState{
		RefreshedAt:    now.Add(-30 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon = checkIdpTokenExpiresSoon(toa, sessionState)

	if !expiresSoon {
		t.Fail()
	}
}

func TestSessionCookiePayloadSerialization(t *testing.T) {
	payload := SessionCookiePayload{
		Ticket:       "test-session-id-123",
		RefreshToken: "refresh-token-value",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	var decoded SessionCookiePayload
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if decoded.Ticket != payload.Ticket {
		t.Errorf("Expected Ticket %q, got %q", payload.Ticket, decoded.Ticket)
	}
	if decoded.RefreshToken != payload.RefreshToken {
		t.Errorf("Expected RefreshToken %q, got %q", payload.RefreshToken, decoded.RefreshToken)
	}
}

func TestSessionCookiePayloadNoRefreshToken(t *testing.T) {
	payload := SessionCookiePayload{
		Ticket: "test-session-id-123",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	// RefreshToken should be omitted from JSON (omitempty)
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if _, exists := raw["rt"]; exists {
		t.Error("Expected refresh token to be omitted from JSON when empty")
	}

	var decoded SessionCookiePayload
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if decoded.Ticket != payload.Ticket {
		t.Errorf("Expected Ticket %q, got %q", payload.Ticket, decoded.Ticket)
	}
	if decoded.RefreshToken != "" {
		t.Errorf("Expected empty RefreshToken, got %q", decoded.RefreshToken)
	}
}

func TestSessionCookiePayloadBackwardCompatibility(t *testing.T) {
	// Simulate a legacy cookie value (plain session ID, not JSON)
	legacyTicket := "a-plain-session-id-not-json"

	var payload SessionCookiePayload
	err := json.Unmarshal([]byte(legacyTicket), &payload)

	// Should fail to parse as JSON
	if err == nil && payload.Ticket != "" {
		t.Error("Legacy plain-text ticket should not parse as SessionCookiePayload")
	}
}

func TestSessionStateCacheFieldsNotSerialized(t *testing.T) {
	state := &session.SessionState{
		Id:              "test-id",
		AccessToken:     "access-token",
		LastValidatedAt: time.Now(),
		CachedClaims:    map[string]interface{}{"sub": "user123"},
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	// LastValidatedAt and CachedClaims should not appear in JSON
	if _, exists := raw["LastValidatedAt"]; exists {
		t.Error("LastValidatedAt should not be serialized")
	}
	if _, exists := raw["CachedClaims"]; exists {
		t.Error("CachedClaims should not be serialized")
	}

	// Deserialize and verify cache fields are zero-valued
	var deserialized session.SessionState
	json.Unmarshal(data, &deserialized)

	if !deserialized.LastValidatedAt.IsZero() {
		t.Error("LastValidatedAt should be zero after deserialization")
	}
	if deserialized.CachedClaims != nil {
		t.Error("CachedClaims should be nil after deserialization")
	}
}
