package session

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

type testRedisValue struct {
	value     string
	expiresAt time.Time
}

type testRedisServer struct {
	listener   net.Listener
	mu         sync.Mutex
	clients    map[net.Conn]struct{}
	values     map[string]testRedisValue
	now        time.Time
	username   string
	password   string
	database   int
	delay      time.Duration
	acceptDone chan struct{}

	acceptedConnections int
	activeCommands      int
	maxActiveCommands   int
	wg                  sync.WaitGroup
}

func newTestRedisServer(t *testing.T) *testRedisServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &testRedisServer{
		listener:   listener,
		clients:    make(map[net.Conn]struct{}),
		values:     make(map[string]testRedisValue),
		now:        time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC),
		acceptDone: make(chan struct{}),
	}
	go server.accept()
	t.Cleanup(server.close)
	return server
}

func (server *testRedisServer) address() string {
	return server.listener.Addr().String()
}

func (server *testRedisServer) accept() {
	defer close(server.acceptDone)
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.mu.Lock()
		server.clients[connection] = struct{}{}
		server.acceptedConnections++
		server.mu.Unlock()
		server.wg.Add(1)
		go server.serve(connection)
	}
}

func (server *testRedisServer) close() {
	_ = server.listener.Close()
	<-server.acceptDone
	server.mu.Lock()
	for connection := range server.clients {
		_ = connection.Close()
	}
	server.mu.Unlock()
	server.wg.Wait()
}

func (server *testRedisServer) serve(connection net.Conn) {
	defer server.wg.Done()
	defer func() {
		server.mu.Lock()
		delete(server.clients, connection)
		server.mu.Unlock()
		_ = connection.Close()
	}()

	reader := bufio.NewReader(connection)
	authenticated := server.password == ""
	selectedDatabase := 0
	for {
		command, err := readTestRedisCommand(reader)
		if err != nil {
			return
		}

		server.mu.Lock()
		server.activeCommands++
		if server.activeCommands > server.maxActiveCommands {
			server.maxActiveCommands = server.activeCommands
		}
		delay := server.delay
		server.mu.Unlock()
		if delay > 0 && strings.EqualFold(command[0], "GET") {
			time.Sleep(delay)
		}

		response := server.run(command, &authenticated, &selectedDatabase)
		_, _ = io.WriteString(connection, response)
		server.mu.Lock()
		server.activeCommands--
		server.mu.Unlock()
	}
}

func (server *testRedisServer) run(command []string, authenticated *bool, selectedDatabase *int) string {
	server.mu.Lock()
	defer server.mu.Unlock()

	switch strings.ToUpper(command[0]) {
	case "AUTH":
		if len(command) == 2 && server.username == "" && command[1] == server.password {
			*authenticated = true
			return "+OK\r\n"
		}
		if len(command) == 3 && command[1] == server.username && command[2] == server.password {
			*authenticated = true
			return "+OK\r\n"
		}
		return "-ERR invalid credentials\r\n"
	}
	if !*authenticated {
		return "-NOAUTH Authentication required\r\n"
	}

	switch strings.ToUpper(command[0]) {
	case "SELECT":
		if len(command) != 2 {
			return "-ERR wrong number of arguments\r\n"
		}
		database, err := strconv.Atoi(command[1])
		if err != nil || database != server.database {
			return "-ERR invalid database\r\n"
		}
		*selectedDatabase = database
		return "+OK\r\n"
	case "SET":
		if *selectedDatabase != server.database || len(command) != 5 || strings.ToUpper(command[3]) != "EX" {
			return "-ERR invalid SET\r\n"
		}
		ttl, err := strconv.Atoi(command[4])
		if err != nil || ttl <= 0 {
			return "-ERR invalid expiration\r\n"
		}
		server.values[command[1]] = testRedisValue{value: command[2], expiresAt: server.now.Add(time.Duration(ttl) * time.Second)}
		return "+OK\r\n"
	case "GET":
		if *selectedDatabase != server.database || len(command) != 2 {
			return "-ERR invalid GET\r\n"
		}
		value, ok := server.values[command[1]]
		if ok && !server.now.Before(value.expiresAt) {
			delete(server.values, command[1])
			ok = false
		}
		if !ok {
			return "$-1\r\n"
		}
		return fmt.Sprintf("$%d\r\n%s\r\n", len(value.value), value.value)
	case "DEL":
		if *selectedDatabase != server.database || len(command) != 2 {
			return "-ERR invalid DEL\r\n"
		}
		_, ok := server.values[command[1]]
		delete(server.values, command[1])
		if ok {
			return ":1\r\n"
		}
		return ":0\r\n"
	default:
		return "-ERR unsupported command\r\n"
	}
}

func readTestRedisCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 4 || line[0] != '*' || !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("invalid array")
	}
	count, err := strconv.Atoi(line[1 : len(line)-2])
	if err != nil || count <= 0 {
		return nil, errors.New("invalid array length")
	}
	command := make([]string, count)
	for index := range command {
		line, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(line) < 4 || line[0] != '$' || !strings.HasSuffix(line, "\r\n") {
			return nil, errors.New("invalid bulk string")
		}
		length, err := strconv.Atoi(line[1 : len(line)-2])
		if err != nil || length < 0 {
			return nil, errors.New("invalid bulk string length")
		}
		data := make([]byte, length+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		if string(data[length:]) != "\r\n" {
			return nil, errors.New("invalid bulk string terminator")
		}
		command[index] = string(data[:length])
	}
	return command, nil
}

func newTestRedisStorage(t *testing.T, server *testRedisServer, maxConnections int, maxAge int) *RedisSessionStorage {
	t.Helper()
	storage, err := CreateRedisSessionStorage(&config.RedisSessionStorageConfig{
		Address:               server.address(),
		Username:              server.username,
		Password:              server.password,
		Database:              server.database,
		KeyPrefix:             "test:sessions:",
		MaxConnections:        maxConnections,
		MaxIdleConnections:    maxConnections,
		ConnectTimeoutSeconds: 2,
		ReadTimeoutSeconds:    2,
		WriteTimeoutSeconds:   2,
		IdleTimeoutSeconds:    60,
	}, maxAge)
	if err != nil {
		t.Fatalf("CreateRedisSessionStorage failed: %v", err)
	}
	storage.poolRegistry = newRedisPoolRegistry(defaultMaxRedisPools)
	return storage
}

func redisStorageTestDependencies() (*logging.Logger, *config.Config) {
	return logging.CreateLogger(logging.LevelError), &config.Config{}
}

func TestRedisSessionStorageRoundTripExpirationAndDelete(t *testing.T) {
	server := newTestRedisServer(t)
	server.username = "session-user"
	server.password = "session-password"
	server.database = 4
	storage := newTestRedisStorage(t, server, 2, 60)
	logger, cfg := redisStorageTestDependencies()
	state := &SessionState{
		Id:                     "9a8799f4-f9f5-4e45-8da8-f54c17547ac2",
		AccessToken:            "access-token",
		RefreshToken:           "refresh-token",
		IsAuthorized:           true,
		TokenExpiresIn:         3600,
		ValidationCacheKey:     "validation-key",
		ValidatedExpiresAt:     time.Now().Add(time.Hour).Unix(),
		ValidatedClaims:        map[string]interface{}{"sub": "user-1"},
		ClaimsRevision:         "claims-revision",
		AuthorizationResults:   map[string]bool{"admin-policy": true},
	}

	ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}
	if ticket != state.Id {
		t.Fatalf("ticket = %q, want %q", ticket, state.Id)
	}
	state.AccessToken = "changed after store"
	retrieved, err := storage.TryGetSession(logger, cfg, ticket)
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}
	if retrieved.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want stored value", retrieved.AccessToken)
	}
	if retrieved.ValidationCacheKey != state.ValidationCacheKey || retrieved.ClaimsRevision != state.ClaimsRevision {
		t.Fatalf("validation cache metadata was not preserved: got %#v", retrieved)
	}
	if !retrieved.AuthorizationResults["admin-policy"] {
		t.Fatalf("authorization decisions were not preserved: got %#v", retrieved.AuthorizationResults)
	}

	server.mu.Lock()
	server.now = server.now.Add(60 * time.Second)
	server.mu.Unlock()
	if _, err := storage.TryGetSession(logger, cfg, ticket); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired TryGetSession error = %v, want ErrSessionNotFound", err)
	}

	state.AccessToken = "replacement"
	if _, err := storage.StoreSession(logger, cfg, state.Id, state); err != nil {
		t.Fatalf("second StoreSession failed: %v", err)
	}
	if err := storage.DeleteSession(logger, cfg, state.Id); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	if _, err := storage.TryGetSession(logger, cfg, ticket); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("deleted TryGetSession error = %v, want ErrSessionNotFound", err)
	}
}

func TestRedisSessionStorageSharesAndReusesBoundedConnections(t *testing.T) {
	server := newTestRedisServer(t)
	server.delay = 40 * time.Millisecond
	first := newTestRedisStorage(t, server, 2, 60)
	second := newTestRedisStorage(t, server, 2, 60)
	second.poolRegistry = first.poolRegistry
	logger, cfg := redisStorageTestDependencies()
	state := &SessionState{Id: "54c41882-98c5-40cb-bf49-76aaac29afb2"}
	if _, err := first.StoreSession(logger, cfg, state.Id, state); err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}
	if _, err := second.TryGetSession(logger, cfg, state.Id); err != nil {
		t.Fatalf("TryGetSession through second middleware storage failed: %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := second.TryGetSession(logger, cfg, state.Id); err != nil {
				t.Errorf("concurrent TryGetSession failed: %v", err)
			}
		}()
	}
	wg.Wait()

	server.mu.Lock()
	acceptedConnections := server.acceptedConnections
	maxActiveCommands := server.maxActiveCommands
	server.mu.Unlock()
	if acceptedConnections != 2 {
		t.Fatalf("accepted connections = %d, want 2 reused pooled connections", acceptedConnections)
	}
	if maxActiveCommands > 2 {
		t.Fatalf("concurrent Redis commands = %d, want at most 2", maxActiveCommands)
	}
}

func TestRedisSessionStorageRejectsInvalidTicketWithoutConnecting(t *testing.T) {
	server := newTestRedisServer(t)
	storage := newTestRedisStorage(t, server, 2, 60)
	logger, cfg := redisStorageTestDependencies()
	_, err := storage.TryGetSession(logger, cfg, "cookie-storage-ticket")
	if !errors.Is(err, ErrInvalidSessionTicket) {
		t.Fatalf("TryGetSession error = %v, want ErrInvalidSessionTicket", err)
	}
	server.mu.Lock()
	acceptedConnections := server.acceptedConnections
	server.mu.Unlock()
	if acceptedConnections != 0 {
		t.Fatalf("accepted connections = %d, want no Redis connection", acceptedConnections)
	}
}

func TestCreateRedisSessionStorageValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *config.RedisSessionStorageConfig
	}{
		{name: "missing configuration"},
		{name: "invalid address", config: &config.RedisSessionStorageConfig{Address: "redis"}},
		{name: "username without password", config: &config.RedisSessionStorageConfig{Username: "user"}},
		{name: "negative database", config: &config.RedisSessionStorageConfig{Database: -1}},
		{name: "too many idle connections", config: &config.RedisSessionStorageConfig{MaxConnections: 2, MaxIdleConnections: 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CreateRedisSessionStorage(test.config, 60); err == nil {
				t.Fatal("CreateRedisSessionStorage succeeded, want error")
			}
		})
	}
}

func TestRedisPoolRegistryBoundsDistinctConfigurations(t *testing.T) {
	registry := newRedisPoolRegistry(2)
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }
	base := redisPoolKey{
		address:            "127.0.0.1:6379",
		maxConnections:     1,
		maxIdleConnections: 1,
		connectTimeout:     time.Second,
		readTimeout:        time.Second,
		writeTimeout:       time.Second,
		idleTimeout:        time.Minute,
	}

	first := base
	first.database = 1
	second := base
	second.database = 2
	third := base
	third.database = 3

	if _, err := registry.acquire(first); err != nil {
		t.Fatalf("acquire first pool: %v", err)
	}
	registry.release(first)
	now = now.Add(time.Second)
	if _, err := registry.acquire(second); err != nil {
		t.Fatalf("acquire second pool: %v", err)
	}
	registry.release(second)
	now = now.Add(time.Second)
	if _, err := registry.acquire(third); err != nil {
		t.Fatalf("acquire third pool: %v", err)
	}
	registry.release(third)

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.pools) != 2 {
		t.Fatalf("pool count = %d, want hard limit 2", len(registry.pools))
	}
	if _, ok := registry.pools[first]; ok {
		t.Fatal("least-recently-used pool was not evicted")
	}
}

func TestRedisPoolRegistryDoesNotEvictPoolsInUse(t *testing.T) {
	registry := newRedisPoolRegistry(1)
	base := redisPoolKey{
		address:            "127.0.0.1:6379",
		maxConnections:     1,
		maxIdleConnections: 1,
		connectTimeout:     time.Second,
		readTimeout:        time.Second,
		writeTimeout:       time.Second,
		idleTimeout:        time.Minute,
	}
	if _, err := registry.acquire(base); err != nil {
		t.Fatalf("acquire first pool: %v", err)
	}
	other := base
	other.database = 1
	if _, err := registry.acquire(other); err == nil {
		t.Fatal("acquired another pool while the bounded registry was in use")
	}
	registry.release(base)
}
