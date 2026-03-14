package session

import (
	"time"

	"github.com/google/uuid"
)

type SessionStorage interface {
	StoreSession(sessionId string, state *SessionState) (string, error)
	TryGetSession(sessionTicket string) (*SessionState, error)
	DeleteSession(sessionId string) error
}

type SessionState struct {
	Id             string    `json:"id"`
	RefreshedAt    time.Time `json:"created_at"`
	AccessToken    string    `json:"access_token"`
	IdToken        string    `json:"id_token"`
	RefreshToken   string    `json:"refresh_token"`
	IsAuthorized   bool      `json:"is_authorized"`
	TokenExpiresIn int       `json:"token_expires_in"`

	// Not serialized - only relevant for in-memory session caching.
	// Avoids expensive JWT signature verification on every request.
	LastValidatedAt time.Time              `json:"-"`
	CachedClaims    map[string]interface{} `json:"-"`
}

func GenerateSessionId() string {
	id := uuid.New()
	return id.String()
}
