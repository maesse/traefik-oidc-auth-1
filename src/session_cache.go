package src

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

const (
	validationCacheVersion    = "validation-cache-v1"
	authorizationCacheVersion = "authorization-cache-v1"
)

var errCachedTokenExpired = errors.New("cached token is expired")

type validationFingerprintConfig struct {
	Version          string
	ProviderURL      string
	ClientID         string
	JWKSURL          string
	TokenValidation  string
	ValidateIssuer   bool
	ValidIssuer      string
	ValidateAudience bool
	ValidAudience    string
	UseUserInfo      bool
}

type authorizationFingerprintConfig struct {
	Version             string
	CheckOnEveryRequest bool
	Assertions          []canonicalClaimAssertion
}

type canonicalClaimAssertion struct {
	Name  string
	AnyOf []string
	AllOf []string
}

func (toa *TraefikOidcAuth) selectedValidationToken(state *session.SessionState) (string, error) {
	if state.Id == "AuthorizationHeader" || state.Id == "AuthorizationCookie" {
		return state.AccessToken, nil
	}

	switch toa.Config.Provider.TokenValidation {
	case "AccessToken", "Introspection":
		return state.AccessToken, nil
	case "IdToken":
		return state.IdToken, nil
	default:
		return "", fmt.Errorf("invalid value %q for TokenValidation", toa.Config.Provider.TokenValidation)
	}
}

func (toa *TraefikOidcAuth) canReuseValidatedSession(state *session.SessionState) bool {
	if state.Id == "AuthorizationHeader" || state.Id == "AuthorizationCookie" {
		return false
	}
	if toa.Config.Provider.TokenValidation == "Introspection" || toa.Config.Provider.UseClaimsFromUserInfoBool {
		return false
	}
	return toa.Config.SessionStorageType == config.SessionStorageTypeRedis ||
		toa.Config.SessionStorageType == config.SessionStorageTypeInMemory
}

func (toa *TraefikOidcAuth) buildValidationConfigFingerprint() (string, error) {
	jwksURL := ""
	if toa.DiscoveryDocument != nil {
		jwksURL = toa.DiscoveryDocument.JWKSURI
	}
	fingerprintConfig := validationFingerprintConfig{
		Version:          validationCacheVersion,
		ProviderURL:      toa.Config.Provider.Url,
		ClientID:         toa.Config.Provider.ClientId,
		JWKSURL:          jwksURL,
		TokenValidation:  toa.Config.Provider.TokenValidation,
		ValidateIssuer:   toa.Config.Provider.ValidateIssuerBool,
		ValidIssuer:      toa.Config.Provider.ValidIssuer,
		ValidateAudience: toa.Config.Provider.ValidateAudienceBool,
		ValidAudience:    toa.Config.Provider.ValidAudience,
		UseUserInfo:      toa.Config.Provider.UseClaimsFromUserInfoBool,
	}
	encodedConfig, err := json.Marshal(fingerprintConfig)
	if err != nil {
		return "", err
	}
	return hashParts(encodedConfig), nil
}

func (toa *TraefikOidcAuth) validationFingerprint(token string) (string, error) {
	configKey := toa.validationCacheConfigKey
	if configKey == "" {
		var err error
		configKey, err = toa.buildValidationConfigFingerprint()
		if err != nil {
			return "", err
		}
	}
	return hashParts([]byte(configKey), []byte(token)), nil
}

func (toa *TraefikOidcAuth) tryValidatedSessionCache(state *session.SessionState, token string) (bool, map[string]interface{}, error) {
	if !toa.canReuseValidatedSession(state) || state.ValidatedClaims == nil || state.ValidatedExpiresAt <= 0 {
		return false, nil, nil
	}

	cacheKey, err := toa.validationFingerprint(token)
	if err != nil || cacheKey != state.ValidationCacheKey {
		return false, nil, err
	}
	if time.Now().Unix() >= state.ValidatedExpiresAt {
		return true, nil, errCachedTokenExpired
	}
	return true, state.ValidatedClaims, nil
}

func (toa *TraefikOidcAuth) cacheValidatedSession(state *session.SessionState, token string, claims map[string]interface{}) bool {
	if !toa.canReuseValidatedSession(state) {
		return false
	}

	expiresAt, ok := claimUnixTime(claims["exp"])
	if !ok || expiresAt <= time.Now().Unix() {
		return false
	}
	cacheKey, err := toa.validationFingerprint(token)
	if err != nil {
		return false
	}
	claimsRevision, err := claimsFingerprint(claims)
	if err != nil {
		return false
	}

	changed := state.ValidationCacheKey != cacheKey || state.ClaimsRevision != claimsRevision
	state.ValidationCacheKey = cacheKey
	state.ValidatedExpiresAt = expiresAt
	state.ValidatedClaims = claims
	state.ClaimsRevision = claimsRevision
	if changed {
		state.AuthorizationResults = nil
	}
	return changed
}

func (toa *TraefikOidcAuth) authorizationDecisionKey(state *session.SessionState, claims map[string]interface{}) (string, bool) {
	token, err := toa.selectedValidationToken(state)
	if err != nil || token == "" {
		return "", false
	}
	validationKey, err := toa.validationFingerprint(token)
	if err != nil {
		return "", false
	}
	claimsRevision := state.ClaimsRevision
	if claimsRevision == "" || state.ValidationCacheKey != validationKey {
		claimsRevision, err = claimsFingerprint(claims)
		if err != nil {
			return "", false
		}
	}
	authorizationKey := toa.authorizationCachePolicyKey
	if authorizationKey == "" {
		authorizationKey, err = authorizationFingerprint(toa.Config.Authorization)
		if err != nil {
			return "", false
		}
	}
	return hashParts([]byte(authorizationCacheVersion), []byte(validationKey), []byte(claimsRevision), []byte(authorizationKey)), true
}

func (toa *TraefikOidcAuth) cachedAuthorizationDecision(state *session.SessionState, claims map[string]interface{}) (bool, bool) {
	key, ok := toa.authorizationDecisionKey(state, claims)
	if !ok || state.AuthorizationResults == nil {
		return false, false
	}
	decision, found := state.AuthorizationResults[key]
	return decision, found
}

func (toa *TraefikOidcAuth) cacheAuthorizationDecision(state *session.SessionState, claims map[string]interface{}, allowed bool) bool {
	key, ok := toa.authorizationDecisionKey(state, claims)
	if !ok {
		return false
	}
	if state.AuthorizationResults == nil {
		state.AuthorizationResults = make(map[string]bool)
	}
	previous, found := state.AuthorizationResults[key]
	state.AuthorizationResults[key] = allowed
	return !found || previous != allowed
}

func authorizationFingerprint(authorization *config.AuthorizationConfig) (string, error) {
	canonical := authorizationFingerprintConfig{Version: authorizationCacheVersion}
	if authorization != nil {
		canonical.CheckOnEveryRequest = authorization.CheckOnEveryRequest
		canonical.Assertions = make([]canonicalClaimAssertion, 0, len(authorization.AssertClaims))
		for _, assertion := range authorization.AssertClaims {
			canonical.Assertions = append(canonical.Assertions, canonicalClaimAssertion{
				Name:  assertion.Name,
				AnyOf: sortedUnique(assertion.AnyOf),
				AllOf: sortedUnique(assertion.AllOf),
			})
		}
		sort.Slice(canonical.Assertions, func(left, right int) bool {
			leftEncoded, _ := json.Marshal(canonical.Assertions[left])
			rightEncoded, _ := json.Marshal(canonical.Assertions[right])
			return string(leftEncoded) < string(rightEncoded)
		})
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return hashParts(encoded), nil
}

func claimsFingerprint(claims map[string]interface{}) (string, error) {
	encoded, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return hashParts(encoded), nil
}

func claimUnixTime(value interface{}) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case float32:
		return int64(typed), true
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	writeIndex := 1
	for readIndex := 1; readIndex < len(result); readIndex++ {
		if result[readIndex] == result[writeIndex-1] {
			continue
		}
		result[writeIndex] = result[readIndex]
		writeIndex++
	}
	return result[:writeIndex]
}

func hashParts(parts ...[]byte) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write(part)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
