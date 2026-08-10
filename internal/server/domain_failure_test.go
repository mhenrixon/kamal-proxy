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
