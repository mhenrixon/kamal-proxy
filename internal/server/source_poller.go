package server

import (
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"
)

const sourcePollTimeout = 10 * time.Second

// sourcePollerConfig configures one polled application endpoint. The payload
// semantics live entirely in OnBody; the poller owns the schedule, the
// conditional-request state, and the transport.
type sourcePollerConfig struct {
	// Service is the owning service's name, for log lines.
	Service string

	// Kind names what is being polled ("domain source", "redirects source"),
	// for log lines.
	Kind string

	// Source is a path (resolved against the service's targets) or an
	// absolute http(s) URL.
	Source string

	// Interval between polls; DefaultTLSDomainsInterval when zero.
	Interval time.Duration

	// Token is sent as a bearer Authorization header when set.
	Token string

	// Endpoint resolves the base URL and Host header for path-mode sources.
	Endpoint func() (baseURL, host string, err error)

	// OnBody parses and applies one successfully fetched payload. Returning an
	// error keeps the previous ETag, so a broken payload is retried rather
	// than answered with 304s until the content changes again.
	OnBody func(body io.Reader) error
}

// sourcePoller polls an application endpoint, honoring ETags, and hands each
// fetched body to the source-specific parser. The poll is the source of
// truth; push refreshes only trigger an immediate re-poll.
type sourcePoller struct {
	config sourcePollerConfig
	client *http.Client

	mu   sync.Mutex
	etag string

	refresh chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newSourcePoller(config sourcePollerConfig) *sourcePoller {
	if config.Interval == 0 {
		config.Interval = DefaultTLSDomainsInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &sourcePoller{
		config:  config,
		client:  &http.Client{Timeout: sourcePollTimeout},
		refresh: make(chan struct{}, 1),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start launches the poll loop, beginning with an immediate poll.
func (s *sourcePoller) Start() {
	s.wg.Add(1)
	go s.run()
}

// Stop cancels the poll loop and waits for it to exit.
func (s *sourcePoller) Stop() {
	s.cancel()
	s.wg.Wait()
}

// Refresh requests an immediate re-poll without waiting for the interval.
func (s *sourcePoller) Refresh() {
	select {
	case s.refresh <- struct{}{}:
	default:
	}
}

// SeedETag primes the conditional-request state from persisted data.
func (s *sourcePoller) SeedETag(etag string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.etag = etag
}

// ETag returns the last ETag received from the source.
func (s *sourcePoller) ETag() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.etag
}

// Private

func (s *sourcePoller) run() {
	defer s.wg.Done()

	s.poll()

	for {
		timer := time.NewTimer(jitteredInterval(s.config.Interval))

		select {
		case <-s.ctx.Done():
			timer.Stop()
			return
		case <-s.refresh:
			timer.Stop()
			s.poll()
		case <-timer.C:
			s.poll()
		}
	}
}

func (s *sourcePoller) poll() {
	url, host, err := s.endpoint()
	if err != nil {
		slog.Warn("Unable to resolve source endpoint", "kind", s.config.Kind, "service", s.config.Service, "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(s.ctx, sourcePollTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("Unable to build source request", "kind", s.config.Kind, "service", s.config.Service, "error", err)
		return
	}

	req.Header.Set("User-Agent", healthCheckUserAgent)
	req.Header.Set("Accept", "application/json")
	if host != "" {
		req.Host = host
	}
	if s.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.Token)
	}

	s.mu.Lock()
	etag := s.etag
	s.mu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("Source poll failed", "kind", s.config.Kind, "service", s.config.Service, "url", url, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		slog.Debug("Source unchanged", "kind", s.config.Kind, "service", s.config.Service)
		return
	}

	if resp.StatusCode != http.StatusOK {
		slog.Warn("Source returned unexpected status", "kind", s.config.Kind, "service", s.config.Service, "status", resp.StatusCode)
		return
	}

	var body io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			slog.Warn("Source returned an unreadable gzip body", "kind", s.config.Kind, "service", s.config.Service, "error", err)
			return
		}
		defer gz.Close()
		body = gz
	}

	// The new ETag is stored before OnBody so the parser's consumers can read
	// it, and rolled back on failure so a broken payload keeps being fetched
	// rather than 304ing until the content changes again.
	newETag := resp.Header.Get("ETag")
	s.mu.Lock()
	previousETag := s.etag
	s.etag = newETag
	s.mu.Unlock()

	if err := s.config.OnBody(body); err != nil {
		s.mu.Lock()
		s.etag = previousETag
		s.mu.Unlock()
		slog.Warn("Source returned an invalid payload", "kind", s.config.Kind, "service", s.config.Service, "error", err)
	}
}

func (s *sourcePoller) endpoint() (url, host string, err error) {
	if !strings.HasPrefix(s.config.Source, "/") {
		return s.config.Source, "", nil
	}

	baseURL, host, err := s.config.Endpoint()
	if err != nil {
		return "", "", err
	}

	return baseURL + s.config.Source, host, nil
}

// jitteredInterval spreads polls by ±10% so many proxies do not thundering-herd
// the app.
func jitteredInterval(interval time.Duration) time.Duration {
	jitter := (rand.Float64()*0.2 - 0.1) * float64(interval)
	return interval + time.Duration(jitter)
}
