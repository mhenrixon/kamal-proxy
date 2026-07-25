package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNormalizePathTimeouts(t *testing.T) {
	tests := []struct {
		name     string
		input    []PathTimeout
		expected []PathTimeout
	}{
		{
			name:     "nil stays nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "adds a leading slash and strips a trailing one",
			input:    []PathTimeout{{PathPrefix: "api/reports/", Timeout: time.Minute}},
			expected: []PathTimeout{{PathPrefix: "/api/reports", Timeout: time.Minute}},
		},
		{
			name:     "root prefix is preserved",
			input:    []PathTimeout{{PathPrefix: "/", Timeout: time.Minute}},
			expected: []PathTimeout{{PathPrefix: "/", Timeout: time.Minute}},
		},
		{
			name: "sorts longest prefix first",
			input: []PathTimeout{
				{PathPrefix: "/api", Timeout: time.Second},
				{PathPrefix: "/api/reports/monthly", Timeout: 3 * time.Second},
				{PathPrefix: "/api/reports", Timeout: 2 * time.Second},
			},
			expected: []PathTimeout{
				{PathPrefix: "/api/reports/monthly", Timeout: 3 * time.Second},
				{PathPrefix: "/api/reports", Timeout: 2 * time.Second},
				{PathPrefix: "/api", Timeout: time.Second},
			},
		},
		{
			name: "equal-length prefixes sort lexicographically",
			input: []PathTimeout{
				{PathPrefix: "/bbb", Timeout: 2 * time.Second},
				{PathPrefix: "/aaa", Timeout: time.Second},
			},
			expected: []PathTimeout{
				{PathPrefix: "/aaa", Timeout: time.Second},
				{PathPrefix: "/bbb", Timeout: 2 * time.Second},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizePathTimeouts(tt.input))
		})
	}
}

func TestNormalizePathTimeouts_DoesNotMutateInput(t *testing.T) {
	input := []PathTimeout{
		{PathPrefix: "/api", Timeout: time.Second},
		{PathPrefix: "api/reports/", Timeout: 2 * time.Second},
	}

	NormalizePathTimeouts(input)

	assert.Equal(t, []PathTimeout{
		{PathPrefix: "/api", Timeout: time.Second},
		{PathPrefix: "api/reports/", Timeout: 2 * time.Second},
	}, input)
}

func TestResolvePathTimeout(t *testing.T) {
	timeouts := NormalizePathTimeouts([]PathTimeout{
		{PathPrefix: "/api", Timeout: 2 * time.Second},
		{PathPrefix: "/api/reports", Timeout: 5 * time.Minute},
		{PathPrefix: "/stream", Timeout: 0},
	})

	tests := []struct {
		name     string
		path     string
		timeouts []PathTimeout
		expected time.Duration
	}{
		{
			name:     "no overrides falls back",
			path:     "/api/reports",
			timeouts: nil,
			expected: time.Second,
		},
		{
			name:     "unmatched path falls back",
			path:     "/other",
			timeouts: timeouts,
			expected: time.Second,
		},
		{
			name:     "exact prefix match",
			path:     "/api",
			timeouts: timeouts,
			expected: 2 * time.Second,
		},
		{
			name:     "match on a path below the prefix",
			path:     "/api/users/1",
			timeouts: timeouts,
			expected: 2 * time.Second,
		},
		{
			name:     "longest prefix wins",
			path:     "/api/reports/monthly",
			timeouts: timeouts,
			expected: 5 * time.Minute,
		},
		{
			name:     "a zero override disables the timeout rather than falling back",
			path:     "/stream/events",
			timeouts: timeouts,
			expected: 0,
		},
		{
			name:     "partial segment does not match",
			path:     "/apiary",
			timeouts: timeouts,
			expected: time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ResolvePathTimeout(tt.path, tt.timeouts, time.Second))
		})
	}
}

func BenchmarkResolvePathTimeout(b *testing.B) {
	b.Run("no overrides", func(b *testing.B) {
		for b.Loop() {
			ResolvePathTimeout("/api/reports/monthly", nil, time.Second)
		}
	})

	b.Run("three overrides", func(b *testing.B) {
		timeouts := NormalizePathTimeouts([]PathTimeout{
			{PathPrefix: "/api", Timeout: 2 * time.Second},
			{PathPrefix: "/api/reports", Timeout: 5 * time.Minute},
			{PathPrefix: "/stream", Timeout: 0},
		})

		for b.Loop() {
			ResolvePathTimeout("/api/reports/monthly", timeouts, time.Second)
		}
	})
}
