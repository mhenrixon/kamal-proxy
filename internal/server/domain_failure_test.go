package server

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
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
			assert.Equal(t, tt.expected, identifyFailedDomains(tt.err, tt.domains, tt.preflight, nil))
		})
	}
}

// rateLimitedProblem builds the error an ACME server returns when it rejects
// new-order with urn:ietf:params:acme:error:rateLimited.
func rateLimitedProblem(detail string) *acme.ProblemDetails {
	return &acme.ProblemDetails{
		Type:       acmeRateLimitedProblem,
		Detail:     detail,
		HTTPStatus: 429,
	}
}

func TestParseRateLimited(t *testing.T) {
	boulderUTC := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		err         error
		ok          bool
		identifiers []string
		retryAfter  time.Time
	}{
		{
			name: "failed authorizations limit names the identifier and retry time",
			err: rateLimitedProblem(`too many failed authorizations (5) for "example.com" in the last 1h0m0s, ` +
				`retry after 2026-08-21 06:00:00 UTC: see https://letsencrypt.org/docs/rate-limits/`),
			ok:          true,
			identifiers: []string{"example.com"},
			retryAfter:  boulderUTC,
		},
		{
			name:        "RFC3339 retry timestamp",
			err:         rateLimitedProblem(`too many failed authorizations (5) for "app.example.com", retry after 2026-08-21T06:00:00Z: see docs`),
			ok:          true,
			identifiers: []string{"app.example.com"},
			retryAfter:  boulderUTC,
		},
		{
			name: "subproblem identifiers are collected",
			err: &acme.ProblemDetails{
				Type:       acmeRateLimitedProblem,
				Detail:     "rate limited",
				HTTPStatus: 429,
				SubProblems: []acme.SubProblem{
					{Identifier: acme.Identifier{Type: "dns", Value: "a.example.com"}},
					{Identifier: acme.Identifier{Type: "dns", Value: "b.example.com"}},
				},
			},
			ok:          true,
			identifiers: []string{"a.example.com", "b.example.com"},
		},
		{
			name:        "quoted non-hostnames are ignored",
			err:         rateLimitedProblem(`too many requests, see "https://letsencrypt.org/docs" or "the docs"`),
			ok:          true,
			identifiers: nil,
		},
		{
			name:        "account-level limit names nothing",
			err:         rateLimitedProblem(`too many new orders recently: see https://letsencrypt.org/docs/rate-limits/`),
			ok:          true,
			identifiers: nil,
		},
		{
			name: "wrapped the way obtainCertificateAt wraps still parses",
			err: fmt.Errorf("DNS-01 issuance failed for %v: %w", []string{"example.com"},
				rateLimitedProblem(`too many failed authorizations (5) for "example.com", retry after 2026-08-21 06:00:00 UTC: see docs`)),
			ok:          true,
			identifiers: []string{"example.com"},
			retryAfter:  boulderUTC,
		},
		{
			name: "other problem types are not rate limits",
			err: &acme.ProblemDetails{
				Type:       "urn:ietf:params:acme:error:unauthorized",
				Detail:     `unauthorized for "example.com"`,
				HTTPStatus: 403,
			},
			ok: false,
		},
		{
			name: "plain errors are not rate limits",
			err:  errors.New("acme: internal error"),
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, ok := parseRateLimited(tt.err)
			assert.Equal(t, tt.ok, ok)
			if !tt.ok {
				return
			}
			assert.Equal(t, tt.identifiers, limit.identifiers)
			if tt.retryAfter.IsZero() {
				assert.True(t, limit.retryAfter.IsZero(), "expected no retry time, got %v", limit.retryAfter)
			} else {
				assert.True(t, tt.retryAfter.Equal(limit.retryAfter),
					"expected retry after %v, got %v", tt.retryAfter, limit.retryAfter)
			}
		})
	}
}

func TestRateLimitedDomains(t *testing.T) {
	tests := []struct {
		name        string
		identifiers []string
		domains     []string
		expected    []string
	}{
		{
			name:        "exact member match",
			identifiers: []string{"b.example.com"},
			domains:     []string{"a.example.com", "b.example.com"},
			expected:    []string{"b.example.com"},
		},
		{
			name:        "wildcard member matched via its authorization name",
			identifiers: []string{"example.com"},
			domains:     []string{"*.example.com", "app.other.com"},
			expected:    []string{"*.example.com"},
		},
		{
			name:        "registered-domain fallback blames every member under it",
			identifiers: []string{"example.com"},
			domains:     []string{"a.example.com", "b.example.com", "app.other.com"},
			expected:    []string{"a.example.com", "b.example.com"},
		},
		{
			name:        "exact match suppresses the registered-domain fallback",
			identifiers: []string{"a.example.com"},
			domains:     []string{"a.example.com", "www.a.example.com"},
			expected:    []string{"a.example.com"},
		},
		{
			name:        "nothing matches",
			identifiers: []string{"unrelated.net"},
			domains:     []string{"a.example.com"},
			expected:    []string{},
		},
		{
			name:        "no identifiers",
			identifiers: nil,
			domains:     []string{"a.example.com"},
			expected:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit := acmeRateLimit{identifiers: tt.identifiers}
			assert.Equal(t, tt.expected, rateLimitedDomains(limit, tt.domains))
		})
	}
}
