package claimbench

import (
	"context"
	"fmt"
	"net/http"
)

type Config struct {
	Mode string `json:"mode"`
}

func CreateConfig() *Config {
	return &Config{Mode: "full"}
}

type middleware struct {
	mode string
}

func New(_ context.Context, _ http.Handler, config *Config, _ string) (http.Handler, error) {
	switch config.Mode {
	case "baseline", "marshal", "jsonpath", "full", "direct", "jwt", "jwt-full":
		if config.Mode == "jwt" || config.Mode == "jwt-full" {
			if err := prepareBenchmarkJWT(); err != nil {
				return nil, fmt.Errorf("prepare benchmark JWT: %w", err)
			}
		}
		return &middleware{mode: config.Mode}, nil
	default:
		return nil, fmt.Errorf("unsupported benchmark mode %q", config.Mode)
	}
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, _ *http.Request) {
	var ok bool

	switch m.mode {
	case "baseline":
		ok = true
	case "marshal":
		_, err := marshalClaims(benchmarkClaims)
		ok = err == nil
	case "jsonpath":
		value, err := selectClaim(benchmarkClaims, "groups")
		ok = err == nil && len(value) > 0
	case "full":
		ok = isAuthorizedJSONPath(benchmarkClaims, benchmarkAssertions)
	case "direct":
		ok = isAuthorizedDirect(benchmarkClaims, benchmarkAssertions)
	case "jwt":
		_, err := validateBenchmarkJWT()
		ok = err == nil
	case "jwt-full":
		var claims map[string]interface{}
		var err error
		claims, err = validateBenchmarkJWT()
		ok = err == nil
		if ok {
			ok = isAuthorizedJSONPath(claims, benchmarkAssertions)
		}
	}

	if !ok {
		http.Error(rw, "authorization benchmark failed", http.StatusForbidden)
		return
	}

	rw.WriteHeader(http.StatusNoContent)
}
