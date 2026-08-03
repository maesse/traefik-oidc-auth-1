package src

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

type opaqueTicketStorage struct {
	stored           *session.SessionState
	deletedSessionId string
}

func (storage *opaqueTicketStorage) StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *session.SessionState) (string, error) {
	storage.stored = state
	return "backend-owned-ticket", nil
}

func (storage *opaqueTicketStorage) TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*session.SessionState, error) {
	return storage.stored, nil
}

func (storage *opaqueTicketStorage) DeleteSession(logger *logging.Logger, config *config.Config, sessionId string) error {
	storage.deletedSessionId = sessionId
	return nil
}

func TestCreateConfigDefaultsToCookieSessionStorage(t *testing.T) {
	cfg := CreateConfig()
	if cfg.SessionStorageType != config.SessionStorageTypeCookie {
		t.Fatalf("SessionStorageType = %q, want %q", cfg.SessionStorageType, config.SessionStorageTypeCookie)
	}
	if cfg.Redis == nil || cfg.Redis.Address != "localhost:6379" || cfg.Redis.MaxConnections != 10 {
		t.Fatalf("unexpected Redis defaults: %#v", cfg.Redis)
	}
}

func TestCreateSessionStorage(t *testing.T) {
	tests := []struct {
		name        string
		storageType string
		wantError   bool
	}{
		{name: "backwards-compatible empty value"},
		{name: "cookie", storageType: config.SessionStorageTypeCookie},
		{name: "unsupported", storageType: "Unknown", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage, err := createSessionStorage(&config.Config{
				Secret:             "01234567890123456789012345678901",
				SessionStorageType: test.storageType,
			})
			if test.wantError {
				if err == nil {
					t.Fatal("createSessionStorage succeeded for an unsupported type")
				}
				return
			}
			if err != nil {
				t.Fatalf("createSessionStorage failed: %v", err)
			}
			if _, ok := storage.(*session.CookieSessionStorage); !ok {
				t.Fatalf("createSessionStorage returned %T, want *session.CookieSessionStorage", storage)
			}
		})
	}
}

func TestCreateInMemorySessionStorage(t *testing.T) {
	storage, err := createSessionStorage(&config.Config{
		SessionStorageType: config.SessionStorageTypeInMemory,
		SessionCookie: &config.SessionCookieConfig{
			MaxAge: 120,
		},
	})
	if err != nil {
		t.Fatalf("createSessionStorage failed: %v", err)
	}
	if _, ok := storage.(*session.InMemorySessionStorage); !ok {
		t.Fatalf("createSessionStorage returned %T, want *session.InMemorySessionStorage", storage)
	}
}

func TestCreateRedisSessionStorage(t *testing.T) {
	storage, err := createSessionStorage(&config.Config{
		SessionStorageType: config.SessionStorageTypeRedis,
		SessionCookie: &config.SessionCookieConfig{
			MaxAge: 120,
		},
		Redis: &config.RedisSessionStorageConfig{
			Address: "localhost:6379",
		},
	})
	if err != nil {
		t.Fatalf("createSessionStorage failed: %v", err)
	}
	if _, ok := storage.(*session.RedisSessionStorage); !ok {
		t.Fatalf("createSessionStorage returned %T, want *session.RedisSessionStorage", storage)
	}
}

func TestStoreSessionTreatsStorageTicketAsOpaque(t *testing.T) {
	storage := &opaqueTicketStorage{}
	toa := &TraefikOidcAuth{
		logger:         logging.CreateLogger(logging.LevelError),
		SessionStorage: storage,
		Config: &config.Config{
			CookieNamePrefix: "TraefikOidcAuth",
			SessionCookie: &config.SessionCookieConfig{
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
			},
		},
	}
	state := &session.SessionState{Id: "session-id"}
	rw := httptest.NewRecorder()

	toa.storeSessionAndAttachCookie(state, rw)

	if storage.stored != state {
		t.Fatal("storage did not receive the session state")
	}
	response := rw.Result()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if cookies[0].Value != "backend-owned-ticket" {
		t.Fatalf("cookie value = %q, want the storage ticket unchanged", cookies[0].Value)
	}
}

func TestLogoutDeletesStoredSessionAndClearsCookie(t *testing.T) {
	storage := &opaqueTicketStorage{}
	toa := &TraefikOidcAuth{
		logger:         logging.CreateLogger(logging.LevelError),
		SessionStorage: storage,
		CallbackURL:    &url.URL{Path: "/oidc/callback"},
		DiscoveryDocument: &oidc.OidcDiscovery{
			EndSessionEndpoint: "https://identity.example/logout",
		},
		Config: &config.Config{
			Secret:                "01234567890123456789012345678901",
			PostLogoutRedirectUri: "/",
			CookieNamePrefix:      "TraefikOidcAuth",
			Provider: &config.ProviderConfig{
				ClientId: "client-id",
			},
			SessionCookie: &config.SessionCookieConfig{
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/logout", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session", Value: "backend-owned-ticket"})
	rw := httptest.NewRecorder()

	toa.handleLogout(rw, req, &session.SessionState{Id: "session-id", IdToken: "id-token"})

	if storage.deletedSessionId != "session-id" {
		t.Fatalf("deleted session = %q, want %q", storage.deletedSessionId, "session-id")
	}
	if rw.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusFound)
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if cookies[0].Name != "TraefikOidcAuth.Session" || cookies[0].MaxAge != -1 {
		t.Fatalf("session cookie was not cleared: %#v", cookies[0])
	}
}

func TestInMemoryStorageRejectsAndClearsCookieStorageChunks(t *testing.T) {
	storage := session.CreateInMemorySessionStorage(60)
	cfg := CreateConfig()
	cfg.UnauthenticatedBehavior = "Unauthorized"
	toa := &TraefikOidcAuth{
		logger:            logging.CreateLogger(logging.LevelError),
		SessionStorage:    storage,
		CallbackURL:       &url.URL{Path: "/oidc/callback"},
		DiscoveryDocument: &oidc.OidcDiscovery{},
		Config:            cfg,
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/protected", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.Chunks", Value: "2"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.1", Value: "legacy-encrypted-"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.2", Value: "cookie-ticket"})
	rw := httptest.NewRecorder()

	toa.ServeHTTP(rw, req)

	cookies := rw.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("got %d Set-Cookie headers, want 3", len(cookies))
	}
	byName := make(map[string]*http.Cookie, len(cookies))
	for _, cookie := range cookies {
		byName[cookie.Name] = cookie
	}
	for _, name := range []string{
		"TraefikOidcAuth.Session.Chunks",
		"TraefikOidcAuth.Session.1",
		"TraefikOidcAuth.Session.2",
	} {
		if cookie := byName[name]; cookie == nil || cookie.MaxAge != -1 {
			t.Fatalf("stale cookie %q was not expired: %#v", name, cookie)
		}
	}
}
