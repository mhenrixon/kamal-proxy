package cmd

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server"
)

func sampleDomainsStatus() server.DomainsStatusResponse {
	return server.DomainsStatusResponse{
		Services: map[string]server.DomainsServiceStatus{
			"tenants": {
				Source: "http://tenants.internal/domains",
				Domains: []server.DomainStatus{
					{Domain: "a.example.com", Certified: true},
					{Domain: "b.example.com", Certified: false},
				},
				FetchedAt:    time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC),
				HeldRemovals: []string{"gone.example.com"},
			},
		},
		QueueLength: 3,
		Quarantine: map[string]server.QuarantineStatus{
			"b.example.com": {
				Until:    time.Date(2026, 8, 26, 14, 32, 10, 0, time.UTC),
				Failures: 2,
				Kind:     "preflight",
			},
		},
		Certificates: 4,
		Registered: map[string]server.RegisteredDomainStatus{
			"web.example.com": {Service: "web", Certified: true, ExpiresAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)},
			"new.example.com": {Service: "web"},
		},
	}
}

func TestDomainsListCommand_JSONFlag(t *testing.T) {
	flag := newDomainsListCommand().cmd.Flags().Lookup("json")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestDomainsStatsCommand_JSONFlag(t *testing.T) {
	flag := newDomainsStatsCommand().cmd.Flags().Lookup("json")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestDomainsListCommand_JSONOutputShape(t *testing.T) {
	data, err := json.Marshal(sampleDomainsStatus())
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))

	quarantine := decoded["quarantine"].(map[string]any)["b.example.com"].(map[string]any)
	assert.Equal(t, "preflight", quarantine["kind"])
	assert.Equal(t, float64(2), quarantine["failures"])
	assert.Equal(t, "2026-08-26T14:32:10Z", quarantine["until"])

	service := decoded["services"].(map[string]any)["tenants"].(map[string]any)
	assert.Equal(t, []any{"gone.example.com"}, service["held_removals"])
	assert.Equal(t, "2026-08-26T10:00:00Z", service["fetched_at"])

	registered := decoded["registered"].(map[string]any)
	assert.Equal(t, "web", registered["web.example.com"].(map[string]any)["service"])
	assert.NotContains(t, registered["new.example.com"].(map[string]any), "expires_at")

	assert.Equal(t, float64(3), decoded["queue_length"])
	assert.Equal(t, float64(4), decoded["certificates"])
}

func TestSummarizeDomains(t *testing.T) {
	tests := []struct {
		name     string
		response server.DomainsStatusResponse
		expected DomainsStatsSummary
	}{
		{
			name:     "empty",
			response: server.DomainsStatusResponse{},
			expected: DomainsStatsSummary{},
		},
		{
			name:     "mixed",
			response: sampleDomainsStatus(),
			expected: DomainsStatsSummary{
				Services:            1,
				DynamicDomains:      2,
				DynamicCertified:    1,
				RegisteredHosts:     2,
				RegisteredCertified: 1,
				Queued:              3,
				Quarantined:         1,
				HeldRemovals:        1,
				Certificates:        4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, summarizeDomains(tt.response))
		})
	}
}

func TestDomainsStatsSummary_JSONKeys(t *testing.T) {
	data, err := json.Marshal(summarizeDomains(sampleDomainsStatus()))
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))

	for _, key := range []string{
		"services", "dynamic_domains", "dynamic_certified", "registered_hosts",
		"registered_certified", "queued", "quarantined", "held_removals", "certificates",
	} {
		assert.Contains(t, decoded, key)
	}
	assert.Equal(t, float64(2), decoded["dynamic_domains"])
}
