package acme

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProviderEntries(t *testing.T) {
	tests := []struct {
		name          string
		entries       []string
		expectDefault ProviderName
		expectZones   map[string]ProviderName
		expectError   string
	}{
		{
			name:          "single bare provider keeps the current form working",
			entries:       []string{"cloudflare"},
			expectDefault: ProviderCloudflare,
		},
		{
			name:          "auto stays the way to pick a default",
			entries:       []string{"auto"},
			expectDefault: ProviderAuto,
		},
		{
			name:          "empty entries mean no configuration",
			entries:       nil,
			expectDefault: "",
		},
		{
			name:    "zone mappings with a bare default",
			entries: []string{"platform.example=cloudflare", "legacy.example=hetzner", "vultr"},
			expectZones: map[string]ProviderName{
				"platform.example": ProviderCloudflare,
				"legacy.example":   ProviderHetzner,
			},
			expectDefault: ProviderVultr,
		},
		{
			name:    "mappings without a default",
			entries: []string{"platform.example=cloudflare"},
			expectZones: map[string]ProviderName{
				"platform.example": ProviderCloudflare,
			},
			expectDefault: "",
		},
		{
			name:    "zones normalize case, trailing dots, and wildcard prefixes",
			entries: []string{"*.Platform.Example.=cloudflare"},
			expectZones: map[string]ProviderName{
				"platform.example": ProviderCloudflare,
			},
		},
		{
			name:    "provider aliases work in mappings",
			entries: []string{"platform.example=cf"},
			expectZones: map[string]ProviderName{
				"platform.example": ProviderCloudflare,
			},
		},
		{
			name:        "two bare entries conflict",
			entries:     []string{"cloudflare", "hetzner"},
			expectError: "multiple default DNS providers",
		},
		{
			name:        "auto cannot be mapped to a zone",
			entries:     []string{"platform.example=auto"},
			expectError: "auto",
		},
		{
			name:        "unknown provider in a mapping fails",
			entries:     []string{"platform.example=clodflare"},
			expectError: "clodflare",
		},
		{
			name:        "unknown bare provider fails",
			entries:     []string{"clodflare"},
			expectError: "clodflare",
		},
		{
			name:        "empty zone fails",
			entries:     []string{"=cloudflare"},
			expectError: "empty zone",
		},
		{
			name:        "duplicate zone fails",
			entries:     []string{"platform.example=cloudflare", "platform.example=hetzner"},
			expectError: "duplicate zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selection, err := ParseProviderEntries(tt.entries)

			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectDefault, selection.Default)
			if tt.expectZones == nil {
				assert.Empty(t, selection.Zones)
			} else {
				assert.Equal(t, tt.expectZones, selection.Zones)
			}
		})
	}
}

func TestProviderSelection_ProviderFor(t *testing.T) {
	selection := ProviderSelection{
		Default: ProviderVultr,
		Zones: map[string]ProviderName{
			"platform.example":     ProviderCloudflare,
			"api.platform.example": ProviderHetzner,
			"legacy.example":       ProviderGoDaddy,
		},
	}

	tests := []struct {
		domain       string
		expect       ProviderName
		expectedZone string
	}{
		{"app.platform.example", ProviderCloudflare, "platform.example"},
		{"platform.example", ProviderCloudflare, "platform.example"},
		{"*.platform.example", ProviderCloudflare, "platform.example"},
		{"v2.api.platform.example", ProviderHetzner, "api.platform.example"},
		{"*.api.platform.example", ProviderHetzner, "api.platform.example"},
		{"www.legacy.example", ProviderGoDaddy, "legacy.example"},
		// Label boundary: a zone matches only whole labels.
		{"notplatform.example", ProviderVultr, ""},
		{"unrelated.net", ProviderVultr, ""},
		{"APP.PLATFORM.EXAMPLE", ProviderCloudflare, "platform.example"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			provider, zone := selection.ProviderFor(tt.domain)
			assert.Equal(t, tt.expect, provider)
			assert.Equal(t, tt.expectedZone, zone)
		})
	}
}

func TestProviderSelection_ProviderFor_NoDefault(t *testing.T) {
	selection := ProviderSelection{
		Zones: map[string]ProviderName{"platform.example": ProviderCloudflare},
	}

	provider, zone := selection.ProviderFor("unrelated.net")
	assert.Equal(t, ProviderName(""), provider)
	assert.Empty(t, zone)
}
