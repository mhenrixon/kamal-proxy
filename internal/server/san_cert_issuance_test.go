package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitWildcardZones(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		expected [][]string
	}{
		{
			name:     "no wildcard: one partition, untouched",
			domains:  []string{"a.example.com", "b.example.net"},
			expected: [][]string{{"a.example.com", "b.example.net"}},
		},
		{
			name: "wildcard and foreign-zone tenant domains never share an order",
			// The exact composition that took a fleet's TLS down: DNS-01
			// cannot edit the tenant's zone, HTTP-01 cannot validate the
			// wildcard, so as one order this is unsatisfiable.
			domains: []string{"*.platform.example", "platform.example", "shop.customer.example", "www.shop.customer.example"},
			expected: [][]string{
				{"*.platform.example", "platform.example"},
				{"shop.customer.example", "www.shop.customer.example"},
			},
		},
		{
			name:    "same-zone hosts ride with their wildcard",
			domains: []string{"*.example.com", "example.com", "a.b.example.com"},
			expected: [][]string{
				{"*.example.com", "example.com", "a.b.example.com"},
			},
		},
		{
			name:    "two wildcards split into two zone partitions",
			domains: []string{"*.one.example", "one.example", "*.two.example", "www.other.example"},
			expected: [][]string{
				{"*.one.example", "one.example"},
				{"*.two.example"},
				{"www.other.example"},
			},
		},
		{
			name:     "wildcard-only set stays one partition",
			domains:  []string{"*.example.com", "example.com"},
			expected: [][]string{{"*.example.com", "example.com"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, splitWildcardZones(tt.domains))
		})
	}
}
