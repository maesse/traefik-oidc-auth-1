package session

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxRedisPools    = 32
	maxRedisResponseSize    = 16 << 20
	maxRedisResponseLineLen = 64 << 10
)

// Traefik may construct the same middleware more than once during dynamic
// configuration changes and does not provide a storage Close hook. The shared,
// size-limited registry lets those instances reuse connections without leaving
// an unbounded set of pools behind after reloads.
var sharedRedisPools = newRedisPoolRegistry(defaultMaxRedisPools)

type redisPoolKey struct {
	address               string
	username              string
	password              string
	database              int
	maxConnections        int
	maxIdleConnections    int
	connectTimeout        time.Duration
	readTimeout           time.Duration
	writeTimeout          time.Duration
	idleTimeout           time.Duration
	tls                   bool
	tlsInsecureSkipVerify bool
}

type redisPoolRegistry struct {
	mu       sync.Mutex
	pools    map[redisPoolKey]*redisPoolEntry
	maxPools int
	now      func() time.Time
}

type redisPoolEntry struct {
	pool     *redisPool
	inUse    int
	lastUsed time.Time
}

func newRedisPoolRegistry(maxPools int) *redisPoolRegistry {
	return &redisPoolRegistry{
		pools:    make(map[redisPoolKey]*redisPoolEntry),
		maxPools: maxPools,
		now:      time.Now,
	}
}

func (registry *redisPoolRegistry) execute(key redisPoolKey, command ...string) (redisValue, error) {
	pool, err := registry.acquire(key)
	if err != nil {
		return redisValue{}, err
	}
	defer registry.release(key)

	return pool.execute(command...)
}

func (registry *redisPoolRegistry) acquire(key redisPoolKey) (*redisPool, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	now := registry.now()
	if entry, ok := registry.pools[key]; ok {
		entry.inUse++
		entry.lastUsed = now
		return entry.pool, nil
	}

	if len(registry.pools) >= registry.maxPools {
		var oldestKey redisPoolKey
		var oldestEntry *redisPoolEntry
		for candidateKey, candidate := range registry.pools {
			if candidate.inUse == 0 && (oldestEntry == nil || candidate.lastUsed.Before(oldestEntry.lastUsed)) {
				oldestKey = candidateKey
				oldestEntry = candidate
			}
		}
		if oldestEntry == nil {
			return nil, fmt.Errorf("too many Redis connection pools in use (maximum %d)", registry.maxPools)
		}
		delete(registry.pools, oldestKey)
		oldestEntry.pool.closeIdle()
	}

	pool := newRedisPool(key)
	registry.pools[key] = &redisPoolEntry{pool: pool, inUse: 1, lastUsed: now}
	return pool, nil
}

func (registry *redisPoolRegistry) release(key redisPoolKey) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if entry, ok := registry.pools[key]; ok && entry.inUse > 0 {
		entry.inUse--
		entry.lastUsed = registry.now()
	}
}

type redisPool struct {
	config redisPoolKey
	slots  chan struct{}
	mu     sync.Mutex
	idle   []redisIdleConnection
	now    func() time.Time
	dial   func(redisPoolKey) (net.Conn, error)
}

type redisIdleConnection struct {
	connection net.Conn
	lastUsed   time.Time
}

func newRedisPool(config redisPoolKey) *redisPool {
	return &redisPool{
		config: config,
		slots:  make(chan struct{}, config.maxConnections),
		now:    time.Now,
		dial:   dialRedisConnection,
	}
}

func (pool *redisPool) execute(command ...string) (redisValue, error) {
	for attempt := 0; attempt < 2; attempt++ {
		connection, reused, err := pool.take()
		if err != nil {
			return redisValue{}, err
		}

		value, err := executeRedisCommand(connection, pool.config, command...)
		if err == nil {
			pool.put(connection, true)
			return value, nil
		}
		pool.put(connection, false)
		if !reused || isRedisServerError(err) {
			return redisValue{}, err
		}
	}

	return redisValue{}, errors.New("Redis command failed")
}

func (pool *redisPool) take() (net.Conn, bool, error) {
	timer := time.NewTimer(pool.config.connectTimeout)
	defer timer.Stop()
	select {
	case pool.slots <- struct{}{}:
	case <-timer.C:
		return nil, false, errors.New("timed out waiting for a Redis connection")
	}

	now := pool.now()
	pool.mu.Lock()
	for len(pool.idle) > 0 {
		last := len(pool.idle) - 1
		entry := pool.idle[last]
		pool.idle = pool.idle[:last]
		if pool.config.idleTimeout > 0 && now.Sub(entry.lastUsed) >= pool.config.idleTimeout {
			_ = entry.connection.Close()
			continue
		}
		pool.mu.Unlock()
		return entry.connection, true, nil
	}
	pool.mu.Unlock()

	connection, err := pool.dial(pool.config)
	if err != nil {
		<-pool.slots
		return nil, false, err
	}
	return connection, false, nil
}

func (pool *redisPool) put(connection net.Conn, reusable bool) {
	pool.mu.Lock()
	if reusable && len(pool.idle) < pool.config.maxIdleConnections {
		pool.idle = append(pool.idle, redisIdleConnection{connection: connection, lastUsed: pool.now()})
	} else {
		_ = connection.Close()
	}
	pool.mu.Unlock()
	<-pool.slots
}

func (pool *redisPool) closeIdle() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, entry := range pool.idle {
		_ = entry.connection.Close()
	}
	pool.idle = nil
}

func dialRedisConnection(config redisPoolKey) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: config.connectTimeout}
	var connection net.Conn
	var err error
	if config.tls {
		host, _, splitErr := net.SplitHostPort(config.address)
		if splitErr != nil {
			return nil, fmt.Errorf("invalid Redis address: %w", splitErr)
		}
		connection, err = tls.DialWithDialer(dialer, "tcp", config.address, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: config.tlsInsecureSkipVerify,
		})
	} else {
		connection, err = dialer.Dial("tcp", config.address)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to Redis: %w", err)
	}

	if config.password != "" {
		command := []string{"AUTH", config.password}
		if config.username != "" {
			command = []string{"AUTH", config.username, config.password}
		}
		value, err := executeRedisCommand(connection, config, command...)
		if err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("authenticate to Redis: %w", err)
		}
		if value.kind != '+' || value.text != "OK" {
			_ = connection.Close()
			return nil, errors.New("authenticate to Redis: unexpected response")
		}
	}
	if config.database != 0 {
		value, err := executeRedisCommand(connection, config, "SELECT", strconv.Itoa(config.database))
		if err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("select Redis database: %w", err)
		}
		if value.kind != '+' || value.text != "OK" {
			_ = connection.Close()
			return nil, errors.New("select Redis database: unexpected response")
		}
	}

	return connection, nil
}

type redisValue struct {
	kind    byte
	text    string
	integer int64
	isNil   bool
}

type redisServerError struct {
	message string
}

func (err *redisServerError) Error() string {
	return "Redis error: " + err.message
}

func isRedisServerError(err error) bool {
	var serverError *redisServerError
	return errors.As(err, &serverError)
}

func executeRedisCommand(connection net.Conn, config redisPoolKey, command ...string) (redisValue, error) {
	if len(command) == 0 {
		return redisValue{}, errors.New("empty Redis command")
	}
	if err := connection.SetWriteDeadline(time.Now().Add(config.writeTimeout)); err != nil {
		return redisValue{}, err
	}
	if err := writeRedisCommand(connection, command); err != nil {
		return redisValue{}, fmt.Errorf("write Redis command: %w", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(config.readTimeout)); err != nil {
		return redisValue{}, err
	}
	value, err := readRedisValue(bufio.NewReader(connection))
	if err != nil {
		return redisValue{}, fmt.Errorf("read Redis response: %w", err)
	}
	return value, nil
}

func writeRedisCommand(writer io.Writer, command []string) error {
	var request strings.Builder
	request.WriteByte('*')
	request.WriteString(strconv.Itoa(len(command)))
	request.WriteString("\r\n")
	for _, argument := range command {
		request.WriteByte('$')
		request.WriteString(strconv.Itoa(len(argument)))
		request.WriteString("\r\n")
		request.WriteString(argument)
		request.WriteString("\r\n")
	}
	encoded := request.String()
	written, err := io.WriteString(writer, encoded)
	if err == nil && written != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}

func readRedisValue(reader *bufio.Reader) (redisValue, error) {
	prefix, err := reader.ReadByte()
	if err != nil {
		return redisValue{}, err
	}

	switch prefix {
	case '+', '-', ':':
		line, err := readRedisLine(reader)
		if err != nil {
			return redisValue{}, err
		}
		if prefix == '-' {
			return redisValue{}, &redisServerError{message: line}
		}
		value := redisValue{kind: prefix, text: line}
		if prefix == ':' {
			value.integer, err = strconv.ParseInt(line, 10, 64)
			if err != nil {
				return redisValue{}, fmt.Errorf("invalid Redis integer: %w", err)
			}
		}
		return value, nil
	case '$':
		line, err := readRedisLine(reader)
		if err != nil {
			return redisValue{}, err
		}
		length, err := strconv.Atoi(line)
		if err != nil || length < -1 || length > maxRedisResponseSize {
			return redisValue{}, errors.New("invalid Redis bulk string length")
		}
		if length == -1 {
			return redisValue{kind: prefix, isNil: true}, nil
		}
		data := make([]byte, length+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return redisValue{}, err
		}
		if data[length] != '\r' || data[length+1] != '\n' {
			return redisValue{}, errors.New("invalid Redis bulk string terminator")
		}
		return redisValue{kind: prefix, text: string(data[:length])}, nil
	default:
		return redisValue{}, fmt.Errorf("unsupported Redis response type %q", prefix)
	}
}

func readRedisLine(reader *bufio.Reader) (string, error) {
	line := make([]byte, 0, 128)
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > maxRedisResponseLineLen {
			return "", errors.New("Redis response line is too long")
		}
		line = append(line, fragment...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
	if len(line) < 2 || string(line[len(line)-2:]) != "\r\n" {
		return "", errors.New("invalid Redis response line terminator")
	}
	return string(line[:len(line)-2]), nil
}
