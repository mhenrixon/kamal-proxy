package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxDomainListBody    = 1 * MB
	maxDomainListEntries = 10000

	domainSourceTimeout = 10 * time.Second
)

type domainSourceConfig struct {
	// Service is the owning service's name.
	Service string

	// Source is a path (resolved against the service's targets) or an
	// absolute http(s) URL.
	Source string

	// Interval between polls; DefaultTLSDomainsInterval when zero.
	Interval time.Duration

	// Token is sent as a bearer Authorization header when set.
	Token string

	// Endpoint resolves the base URL and Host header for path-mode sources.
	Endpoint func() (baseURL, host string, err error)

	// OnDomains receives each successfully fetched, validated domain list.
	OnDomains func(domains []string)
}

// domainSource polls a service's domain list endpoint, honoring ETags, and
// hands validated domain sets to the coordinator. The poll is the source of
// truth; push refreshes only trigger an immediate re-poll.
type domainSource struct {
	config domainSourceConfig
	client *http.Client

	mu   sync.Mutex
	etag string

	refresh chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newDomainSource(config domainSourceConfig) *domainSource {
	if config.Interval == 0 {
		config.Interval = DefaultTLSDomainsInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &domainSource{
		config:  config,
		client:  &http.Client{Timeout: domainSourceTimeout},
		refresh: make(chan struct{}, 1),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start launches the poll loop, beginning with an immediate poll.
func (s *domainSource) Start() {
	s.wg.Add(1)
	go s.run()
}

// Stop cancels the poll loop and waits for it to exit.
func (s *domainSource) Stop() {
	s.cancel()
	s.wg.Wait()
}

// Refresh requests an immediate re-poll without waiting for the interval.
func (s *domainSource) Refresh() {
	select {
	case s.refresh <- struct{}{}:
	default:
	}
}

// SeedETag primes the conditional-request state from persisted data.
func (s *domainSource) SeedETag(etag string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.etag = etag
}

// ETag returns the last ETag received from the source.
func (s *domainSource) ETag() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.etag
}

// Private

func (s *domainSource) run() {
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

func (s *domainSource) poll() {
	url, host, err := s.endpoint()
	if err != nil {
		slog.Warn("Unable to resolve domain source endpoint", "service", s.config.Service, "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(s.ctx, domainSourceTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("Unable to build domain source request", "service", s.config.Service, "error", err)
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
		slog.Warn("Domain source poll failed", "service", s.config.Service, "url", url, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		slog.Debug("Domain source unchanged", "service", s.config.Service)
		return
	}

	if resp.StatusCode != http.StatusOK {
		slog.Warn("Domain source returned unexpected status", "service", s.config.Service, "status", resp.StatusCode)
		return
	}

	domains, err := parseDomainList(resp.Body)
	if err != nil {
		slog.Warn("Domain source returned an invalid payload", "service", s.config.Service, "error", err)
		return
	}

	s.mu.Lock()
	s.etag = resp.Header.Get("ETag")
	s.mu.Unlock()

	s.config.OnDomains(domains)
}

func (s *domainSource) endpoint() (url, host string, err error) {
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

// parseDomainList decodes and validates a domain source payload:
// {"domains": ["tenant.example.com", ...]}. Wildcard and malformed entries are
// skipped; oversized payloads are rejected outright.
func parseDomainList(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDomainListBody+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read domain list: %w", err)
	}
	if int64(len(data)) > maxDomainListBody {
		return nil, fmt.Errorf("domain list too large (over %d bytes)", maxDomainListBody)
	}

	var payload struct {
		Domains []string `json:"domains"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse domain list: %w", err)
	}

	if len(payload.Domains) > maxDomainListEntries {
		return nil, fmt.Errorf("too many domains (%d, max %d)", len(payload.Domains), maxDomainListEntries)
	}

	seen := make(map[string]struct{}, len(payload.Domains))
	domains := []string{}
	for _, raw := range payload.Domains {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))

		if strings.HasPrefix(domain, "*.") {
			slog.Warn("Skipping wildcard entry in domain source; wildcards require DNS-01", "domain", raw)
			continue
		}
		if !validDynamicDomain(domain) {
			slog.Warn("Skipping invalid domain in domain source", "domain", raw)
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}

		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}

	return domains, nil
}

// validDynamicDomain checks the RFC 1123 hostname grammar: at least two
// labels, each 1-63 characters of [a-z0-9-] without leading/trailing hyphens,
// and a top-level label containing a letter (which excludes IP addresses).
func validDynamicDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}

	tld := labels[len(labels)-1]
	for i := 0; i < len(tld); i++ {
		if tld[i] >= 'a' && tld[i] <= 'z' {
			return true
		}
	}
	return false
}
