package src

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

const profileIDHeader = "X-Oidc-Profile-Id"

type requestProfileContextKey struct{}

// profileEvent is deliberately shaped as a tracing event: a name, start offset, and duration.
// A future tracing adapter can emit these records without changing the instrumented call sites.
type profileEvent struct {
	name        string
	startOffset time.Duration
	duration    time.Duration
}

type requestProfile struct {
	id           string
	started      time.Time
	serverTiming bool
	events       []profileEvent
}

type profileStage struct {
	profile *requestProfile
	name    string
	started time.Time
}

func startRequestProfile(cfg *config.ProfilingConfig, rw http.ResponseWriter, req *http.Request) (*http.Request, *requestProfile) {
	if cfg == nil || !cfg.Enabled {
		return req, nil
	}

	started := time.Now()
	profile := &requestProfile{
		id:           fmt.Sprintf("%x", started.UnixNano()),
		started:      started,
		serverTiming: cfg.ServerTiming,
		events:       make([]profileEvent, 0, 16),
	}
	rw.Header().Set(profileIDHeader, profile.id)

	ctx := context.WithValue(req.Context(), requestProfileContextKey{}, profile)
	return req.WithContext(ctx), profile
}

func beginProfileStage(ctx context.Context, name string) profileStage {
	profile, _ := ctx.Value(requestProfileContextKey{}).(*requestProfile)
	if profile == nil {
		return profileStage{}
	}
	return profileStage{profile: profile, name: name, started: time.Now()}
}

func (stage profileStage) End() {
	if stage.profile == nil {
		return
	}
	ended := time.Now()
	stage.profile.events = append(stage.profile.events, profileEvent{
		name:        stage.name,
		startOffset: stage.started.Sub(stage.profile.started),
		duration:    ended.Sub(stage.started),
	})
}

func (profile *requestProfile) PublishServerTiming(rw http.ResponseWriter) {
	if profile == nil || !profile.serverTiming {
		return
	}

	metrics := profile.aggregateEvents()
	values := make([]string, 0, len(metrics))
	for _, metric := range metrics {
		values = append(values, fmt.Sprintf("%s;dur=%.3f", serverTimingName(metric.name), durationMilliseconds(metric.duration)))
	}
	if len(values) > 0 {
		rw.Header().Set("Server-Timing", strings.Join(values, ", "))
	}
}

func (profile *requestProfile) Log(logger *logging.Logger, req *http.Request) {
	if profile == nil {
		return
	}

	metrics := profile.aggregateEvents()
	values := make([]string, 0, len(metrics))
	for _, metric := range metrics {
		values = append(values, fmt.Sprintf("%s=%.3f", metric.name, durationMilliseconds(metric.duration)))
	}

	logger.Log(
		logging.LevelInfo,
		"Profile id=%s method=%s host=%s path=%q total_ms=%.3f stages=%q",
		profile.id,
		req.Method,
		req.Host,
		req.URL.Path,
		durationMilliseconds(time.Since(profile.started)),
		strings.Join(values, ","),
	)
}

func (profile *requestProfile) aggregateEvents() []profileEvent {
	result := make([]profileEvent, 0, len(profile.events))
	indexes := make(map[string]int, len(profile.events))
	for _, event := range profile.events {
		if index, ok := indexes[event.name]; ok {
			result[index].duration += event.duration
			continue
		}
		indexes[event.name] = len(result)
		result = append(result, event)
	}
	return result
}

func serverTimingName(name string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-' {
			return character
		}
		return '_'
	}, name)
}

func durationMilliseconds(duration time.Duration) float64 {
	return float64(duration.Nanoseconds()) / float64(time.Millisecond)
}
