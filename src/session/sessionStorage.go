package session

import (
	"time"

	"github.com/google/uuid"
	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

// SessionStorage owns the contents of the opaque ticket transported in the
// session cookie. Implementations may put the complete session in the ticket or
// use it as a reference to state stored elsewhere.
type SessionStorage interface {
	StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error)
	TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error)
	DeleteSession(logger *logging.Logger, config *config.Config, sessionId string) error
}

type SessionState struct {
	Id             string    `json:"id"`
	RefreshedAt    time.Time `json:"created_at"`
	AccessToken    string    `json:"access_token"`
	IdToken        string    `json:"id_token"`
	RefreshToken   string    `json:"refresh_token"`
	IsAuthorized   bool      `json:"is_authorized"` // Legacy field; never trusted across middleware policies.
	TokenExpiresIn int       `json:"token_expires_in"`

	// The validation cache is populated only after full local JWT validation. Server-side storage
	// can then reuse the effective claims until the exact token, validation configuration, or
	// verified expiration changes.
	ValidationCacheKey string                 `json:"validation_cache_key,omitempty"`
	ValidatedExpiresAt int64                  `json:"validated_expires_at,omitempty"`
	ValidatedClaims    map[string]interface{} `json:"validated_claims,omitempty"`
	ClaimsRevision     string                 `json:"claims_revision,omitempty"`

	// Authorization decisions are scoped to the authentication cache key, effective claims, and
	// canonical authorization policy. Identical middleware configurations therefore share results,
	// while a more privileged policy can never reuse a less privileged policy's boolean.
	AuthorizationResults map[string]bool `json:"authorization_results,omitempty"`

	// Set when this session was (re-)established via a redirect triggered by UnauthorizedBehavior's
	// Challenge, regardless of whether the resulting session ends up authorized - the callback may be
	// handled by a different, more permissive middleware instance than the one that failed the check.
	// Used to avoid redirecting to the IDP again for the same session, which would otherwise risk an
	// infinite redirect loop.
	ChallengeAttempted bool `json:"challenge_attempted"`
}

func GenerateSessionId() string {
	id := uuid.New()
	return id.String()
}
