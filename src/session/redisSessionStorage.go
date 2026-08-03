package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

const (
	defaultRedisAddress               = "localhost:6379"
	defaultRedisKeyPrefix             = "traefik-oidc-auth:session:"
	defaultRedisMaxConnections        = 10
	defaultRedisConnectTimeoutSeconds = 5
	defaultRedisReadTimeoutSeconds    = 3
	defaultRedisWriteTimeoutSeconds   = 3
	defaultRedisIdleTimeoutSeconds    = 60
)

type RedisSessionStorage struct {
	poolRegistry *redisPoolRegistry
	poolKey      redisPoolKey
	keyPrefix    string
	maxAge       time.Duration
}

func CreateRedisSessionStorage(redisConfig *config.RedisSessionStorageConfig, maxAgeSeconds int) (*RedisSessionStorage, error) {
	if redisConfig == nil {
		return nil, errors.New("missing Redis session storage configuration")
	}

	address := redisConfig.Address
	if address == "" {
		address = defaultRedisAddress
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("invalid Redis address %q: %w", address, err)
	}
	if redisConfig.Username != "" && redisConfig.Password == "" {
		return nil, errors.New("Redis username requires a password")
	}
	if redisConfig.Database < 0 {
		return nil, errors.New("Redis database must not be negative")
	}

	keyPrefix := redisConfig.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = defaultRedisKeyPrefix
	}
	maxConnections := redisConfig.MaxConnections
	if maxConnections <= 0 {
		maxConnections = defaultRedisMaxConnections
	}
	maxIdleConnections := redisConfig.MaxIdleConnections
	if maxIdleConnections <= 0 {
		maxIdleConnections = maxConnections
	}
	if maxIdleConnections > maxConnections {
		return nil, errors.New("Redis MaxIdleConnections must not exceed MaxConnections")
	}

	connectTimeout := durationFromSeconds(redisConfig.ConnectTimeoutSeconds, defaultRedisConnectTimeoutSeconds)
	readTimeout := durationFromSeconds(redisConfig.ReadTimeoutSeconds, defaultRedisReadTimeoutSeconds)
	writeTimeout := durationFromSeconds(redisConfig.WriteTimeoutSeconds, defaultRedisWriteTimeoutSeconds)
	idleTimeout := durationFromSeconds(redisConfig.IdleTimeoutSeconds, defaultRedisIdleTimeoutSeconds)
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = defaultServerSideSessionMaxAge
	}

	return &RedisSessionStorage{
		poolRegistry: sharedRedisPools,
		poolKey: redisPoolKey{
			address:               address,
			username:              redisConfig.Username,
			password:              redisConfig.Password,
			database:              redisConfig.Database,
			maxConnections:        maxConnections,
			maxIdleConnections:    maxIdleConnections,
			connectTimeout:        connectTimeout,
			readTimeout:           readTimeout,
			writeTimeout:          writeTimeout,
			idleTimeout:           idleTimeout,
			tls:                   redisConfig.TLS,
			tlsInsecureSkipVerify: redisConfig.TLSInsecureSkipVerify,
		},
		keyPrefix: keyPrefix,
		maxAge:    time.Duration(maxAgeSeconds) * time.Second,
	}, nil
}

func durationFromSeconds(value int, defaultValue int) time.Duration {
	if value <= 0 {
		value = defaultValue
	}
	return time.Duration(value) * time.Second
}

func (storage *RedisSessionStorage) StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error) {
	if state == nil || sessionId == "" {
		return "", errors.New("session state has no id")
	}
	if _, err := uuid.Parse(sessionId); err != nil {
		return "", fmt.Errorf("session state has an invalid id: %w", err)
	}

	data, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("serialize session state: %w", err)
	}
	value, err := storage.poolRegistry.execute(
		storage.poolKey,
		"SET",
		storage.keyPrefix+sessionId,
		string(data),
		"EX",
		strconv.FormatInt(int64(storage.maxAge/time.Second), 10),
	)
	if err != nil {
		return "", fmt.Errorf("store session in Redis: %w", err)
	}
	if value.kind != '+' || value.text != "OK" {
		return "", errors.New("store session in Redis: unexpected response")
	}
	return sessionId, nil
}

func (storage *RedisSessionStorage) TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error) {
	if _, err := uuid.Parse(sessionTicket); err != nil {
		return nil, fmt.Errorf("%w: expected a session id", ErrInvalidSessionTicket)
	}

	value, err := storage.poolRegistry.execute(storage.poolKey, "GET", storage.keyPrefix+sessionTicket)
	if err != nil {
		return nil, fmt.Errorf("load session from Redis: %w", err)
	}
	if value.isNil {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, sessionTicket)
	}
	if value.kind != '$' {
		return nil, errors.New("load session from Redis: unexpected response type")
	}

	var state SessionState
	if err := json.Unmarshal([]byte(value.text), &state); err != nil {
		return nil, fmt.Errorf("deserialize session state from Redis: %w", err)
	}
	return &state, nil
}

func (storage *RedisSessionStorage) DeleteSession(logger *logging.Logger, config *config.Config, sessionId string) error {
	if sessionId == "" {
		return nil
	}
	if _, err := uuid.Parse(sessionId); err != nil {
		return fmt.Errorf("session state has an invalid id: %w", err)
	}
	value, err := storage.poolRegistry.execute(storage.poolKey, "DEL", storage.keyPrefix+sessionId)
	if err != nil {
		return fmt.Errorf("delete session from Redis: %w", err)
	}
	if value.kind != ':' {
		return errors.New("delete session from Redis: unexpected response")
	}
	return nil
}
