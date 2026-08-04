package src

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func newSessionCacheTestAuth(assertions []config.ClaimAssertion) *TraefikOidcAuth {
	return &TraefikOidcAuth{Config: &config.Config{
		SessionStorageType: config.SessionStorageTypeRedis,
		Provider: &config.ProviderConfig{
			TokenValidation:      "IdToken",
			ValidateIssuerBool:   true,
			ValidIssuer:          "https://issuer.example",
			ValidateAudienceBool: true,
			ValidAudience:        "test-client",
		},
		Authorization: &config.AuthorizationConfig{AssertClaims: assertions},
	}}
}

func futureClaims(groups ...interface{}) map[string]interface{} {
	return map[string]interface{}{
		"sub":    "user-1",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"groups": groups,
	}
}

func TestValidatedSessionCacheReusesExactTokenWithoutJWTParsing(t *testing.T) {
	toa := newSessionCacheTestAuth(nil)
	state := &session.SessionState{Id: "server-session", IdToken: "header.payload.signature"}
	claims := futureClaims("admins")

	if !toa.cacheValidatedSession(state, state.IdToken, claims) {
		t.Fatal("initial validation did not populate the session cache")
	}

	ok, actualClaims, err := toa.validateToken(context.Background(), state)
	if err != nil || !ok {
		t.Fatalf("validateToken cache hit = (%v, %v), want successful cache hit", ok, err)
	}
	if actualClaims["sub"] != claims["sub"] {
		t.Fatalf("cached claims sub = %v, want %v", actualClaims["sub"], claims["sub"])
	}
}

func TestValidatedSessionCacheMissesWhenTokenOrValidationConfigChanges(t *testing.T) {
	toa := newSessionCacheTestAuth(nil)
	state := &session.SessionState{Id: "server-session", IdToken: "token-one"}
	toa.cacheValidatedSession(state, state.IdToken, futureClaims("admins"))

	if found, _, err := toa.tryValidatedSessionCache(state, "token-two"); found || err != nil {
		t.Fatalf("changed token cache lookup = (%v, %v), want clean miss", found, err)
	}

	toa.Config.Provider.ValidAudience = "different-client"
	if found, _, err := toa.tryValidatedSessionCache(state, state.IdToken); found || err != nil {
		t.Fatalf("changed validation config cache lookup = (%v, %v), want clean miss", found, err)
	}
}

func TestValidatedSessionCacheStillEnforcesVerifiedExpiration(t *testing.T) {
	toa := newSessionCacheTestAuth(nil)
	state := &session.SessionState{
		Id:                 "server-session",
		IdToken:            "header.payload.signature",
		ValidatedClaims:    futureClaims("admins"),
		ValidatedExpiresAt: time.Now().Add(-time.Second).Unix(),
		ValidationCacheKey: "",
	}
	cacheKey, err := toa.validationFingerprint(state.IdToken)
	if err != nil {
		t.Fatal(err)
	}
	state.ValidationCacheKey = cacheKey

	found, _, err := toa.tryValidatedSessionCache(state, state.IdToken)
	if !found || !errors.Is(err, errCachedTokenExpired) {
		t.Fatalf("expired cache lookup = (%v, %v), want expired hit", found, err)
	}
}

func TestAuthorizationDecisionIsPolicyAndClaimsScoped(t *testing.T) {
	adminPolicy := []config.ClaimAssertion{{Name: "groups", AnyOf: []string{"owners", "admins"}}}
	toa := newSessionCacheTestAuth(adminPolicy)
	state := &session.SessionState{Id: "server-session", IdToken: "header.payload.signature"}
	claims := futureClaims("admins")
	toa.cacheValidatedSession(state, state.IdToken, claims)

	if !toa.cacheAuthorizationDecision(state, claims, true) {
		t.Fatal("initial authorization decision was not cached")
	}
	if allowed, found := toa.cachedAuthorizationDecision(state, claims); !found || !allowed {
		t.Fatalf("same-policy decision = (%v, %v), want cached allow", allowed, found)
	}

	// Ordering does not change policy semantics or the cross-instance fingerprint.
	equivalentInstance := newSessionCacheTestAuth([]config.ClaimAssertion{{Name: "groups", AnyOf: []string{"admins", "owners", "admins"}}})
	if allowed, found := equivalentInstance.cachedAuthorizationDecision(state, claims); !found || !allowed {
		t.Fatalf("equivalent-policy decision = (%v, %v), want shared cached allow", allowed, found)
	}

	higherPolicy := newSessionCacheTestAuth([]config.ClaimAssertion{{Name: "groups", AnyOf: []string{"owners"}}})
	if allowed, found := higherPolicy.cachedAuthorizationDecision(state, claims); found || allowed {
		t.Fatalf("different-policy decision = (%v, %v), want cache miss", allowed, found)
	}

	updatedClaims := futureClaims("owners")
	toa.cacheValidatedSession(state, state.IdToken, updatedClaims)
	if _, found := toa.cachedAuthorizationDecision(state, updatedClaims); found {
		t.Fatal("authorization decision survived a claims revision")
	}
}

func TestLegacyGlobalAuthorizationBooleanIsNeverACacheHit(t *testing.T) {
	toa := newSessionCacheTestAuth([]config.ClaimAssertion{{Name: "groups", AnyOf: []string{"owners"}}})
	state := &session.SessionState{Id: "server-session", IdToken: "header.payload.signature", IsAuthorized: true}
	claims := futureClaims("internal-users")

	if allowed, found := toa.cachedAuthorizationDecision(state, claims); found || allowed {
		t.Fatalf("legacy IsAuthorized produced decision = (%v, %v), want cache miss", allowed, found)
	}
}

func TestDynamicAndExternalTokensNeverUseValidationCache(t *testing.T) {
	toa := newSessionCacheTestAuth(nil)
	state := &session.SessionState{Id: "server-session", IdToken: "token"}

	toa.Config.Provider.TokenValidation = "Introspection"
	if toa.canReuseValidatedSession(state) {
		t.Fatal("introspection unexpectedly enabled validation caching")
	}

	toa.Config.Provider.TokenValidation = "IdToken"
	toa.Config.Provider.UseClaimsFromUserInfoBool = true
	if toa.canReuseValidatedSession(state) {
		t.Fatal("UserInfo unexpectedly enabled validation caching")
	}

	toa.Config.Provider.UseClaimsFromUserInfoBool = false
	state.Id = "AuthorizationHeader"
	if toa.canReuseValidatedSession(state) {
		t.Fatal("external Authorization header unexpectedly enabled validation caching")
	}
}
