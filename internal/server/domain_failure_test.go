package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentifyFailedDomains(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com"}
	failB := func(domain string) error {
		if domain == "b.example.com" {
			return errors.New("does not route here")
		}
		return nil
	}
	failAll := func(domain string) error { return errors.New("does not route here") }
	passAll := func(domain string) error { return nil }

	tests := []struct {
		name      string
		err       error
		domains   []string
		preflight func(string) error
		expected  []string
	}{
		{
			name:      "per-domain error lines take precedence over probing",
			err:       fmt.Errorf("error: one or more domains had a problem:\na.example.com: acme: dns problem"),
			domains:   domains,
			preflight: failB,
			expected:  []string{"a.example.com"},
		},
		{
			name:      "probe names the culprit when the error does not",
			err:       errors.New("acme: internal error"),
			domains:   domains,
			preflight: failB,
			expected:  []string{"b.example.com"},
		},
		{
			name:      "everything passes probing: the whole batch is held",
			err:       errors.New("acme: internal error"),
			domains:   domains,
			preflight: passAll,
			expected:  domains,
		},
		{
			name:     "no probe available: the whole batch is held",
			err:      errors.New("acme: internal error"),
			domains:  domains,
			expected: domains,
		},
		{
			name:      "wildcard members are never probed",
			err:       errors.New("acme: internal error"),
			domains:   []string{"*.example.com", "a.example.com"},
			preflight: failAll,
			expected:  []string{"a.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, identifyFailedDomains(tt.err, tt.domains, tt.preflight))
		})
	}
}

func TestIdentifyFailedDomains_RateLimitedIdentifier(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com", "www.example.net"}
	failAll := func(domain string) error { return errors.New("does not route here") }

	// Let's Encrypt's shape, verbatim: the order is rejected at new-order, so
	// no per-domain "<domain>: <cause>" lines exist and every member would
	// pass or fail preflight identically — only the quoted identifier tells
	// us who is actually throttled.
	err := fmt.Errorf("acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: " +
		"urn:ietf:params:acme:error:rateLimited :: too many failed authorizations (5) for \"www.example.net\" " +
		"in the last 1h0m0s, retry after 2026-08-21 06:27:45 UTC: see " +
		"https://letsencrypt.org/docs/rate-limits/#authorization-failures-per-identifier-per-account")

	assert.Equal(t, []string{"www.example.net"}, identifyFailedDomains(err, domains, failAll),
		"only the throttled identifier is condemned; batch-mates stay issuable")
}

func TestRateLimitedDomains(t *testing.T) {
	domains := []string{"a.example.com", "www.example.net"}

	tests := []struct {
		name     string
		err      error
		expected []string
	}{
		{
			name:     "quoted batch member is attributed",
			err:      errors.New(`urn:ietf:params:acme:error:rateLimited :: too many failed authorizations (5) for "www.example.net" in the last 1h0m0s`),
			expected: []string{"www.example.net"},
		},
		{
			name: "account-scoped limit names no member: caller handles the batch",
			err:  errors.New(`urn:ietf:params:acme:error:rateLimited :: too many new orders recently`),
		},
		{
			name: "quoted stranger is not attributed",
			err:  errors.New(`urn:ietf:params:acme:error:rateLimited :: too many failed authorizations (5) for "other.example.org"`),
		},
		{
			name: "non-rate-limit errors are ignored",
			err:  errors.New(`acme: error: 400 :: urn:ietf:params:acme:error:malformed :: bad CSR for "www.example.net"`),
		},
		{
			name: "nil error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rateLimitedDomains(tt.err, domains))
		})
	}
}
