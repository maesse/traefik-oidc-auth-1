package src

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
)

func TestStartRequestProfileDisabled(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.test/", nil)
	rw := httptest.NewRecorder()

	profiledRequest, profile := startRequestProfile(&config.ProfilingConfig{}, rw, req)
	if profile != nil {
		t.Fatal("disabled profiling returned a profile")
	}
	if profiledRequest != req {
		t.Fatal("disabled profiling replaced the request")
	}
	if value := rw.Header().Get(profileIDHeader); value != "" {
		t.Fatalf("disabled profiling added %s=%q", profileIDHeader, value)
	}
}

func TestRequestProfileAggregatesEventsAndPublishesServerTiming(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.test/private", nil)
	rw := httptest.NewRecorder()

	profiledRequest, profile := startRequestProfile(&config.ProfilingConfig{Enabled: true, ServerTiming: true}, rw, req)
	if profile == nil {
		t.Fatal("enabled profiling returned no profile")
	}
	if profiledRequest == req {
		t.Fatal("enabled profiling did not attach a request context")
	}

	profile.events = append(profile.events,
		profileEvent{name: "session.load", duration: 2 * time.Millisecond},
		profileEvent{name: "jwt.parse", duration: 3 * time.Millisecond},
		profileEvent{name: "jwt.parse", duration: 4 * time.Millisecond},
	)
	profile.PublishServerTiming(rw)

	header := rw.Header().Get("Server-Timing")
	if !strings.Contains(header, "session_load;dur=2.000") {
		t.Fatalf("Server-Timing %q does not contain session metric", header)
	}
	if !strings.Contains(header, "jwt_parse;dur=7.000") {
		t.Fatalf("Server-Timing %q does not contain aggregated JWT metric", header)
	}
	if rw.Header().Get(profileIDHeader) == "" {
		t.Fatalf("enabled profiling did not add %s", profileIDHeader)
	}
}

func TestBeginProfileStageWithoutProfileIsNoOp(t *testing.T) {
	stage := beginProfileStage(context.Background(), "test")
	stage.End()
}
