package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

const (
	maxDomainListBody    = 1 * MB
	maxDomainListEntries = 10000
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

// domainSource polls a service's domain list endpoint and hands validated
// domain sets to the coordinator. The schedule, ETag handling, and transport
// live in sourcePoller; only the payload semantics are here.
type domainSource = sourcePoller

func newDomainSource(config domainSourceConfig) *domainSource {
	return newSourcePoller(sourcePollerConfig{
		Service:  config.Service,
		Kind:     "domain source",
		Source:   config.Source,
		Interval: config.Interval,
		Token:    config.Token,
		Endpoint: config.Endpoint,
		OnBody: func(body io.Reader) error {
			domains, err := parseDomainList(body)
			if err != nil {
				return err
			}

			config.OnDomains(domains)
			return nil
		},
	})
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
