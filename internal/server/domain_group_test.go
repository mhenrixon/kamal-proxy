package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainGrouper_AnalyzeDomains_EmptyInput(t *testing.T) {
	grouper := NewDomainGrouper()
	analysis := grouper.AnalyzeDomains([]string{})

	assert.Empty(t, analysis.Groups)
	assert.Equal(t, 0, analysis.TotalDomains)
	assert.Equal(t, 0, analysis.TotalCerts)
}

func TestDomainGrouper_AnalyzeDomains_SingleDomain(t *testing.T) {
	grouper := NewDomainGrouper()
	analysis := grouper.AnalyzeDomains([]string{"app.example.com"})

	require.Len(t, analysis.Groups, 1)
	assert.Equal(t, "example.com", analysis.Groups[0].RootDomain)
	assert.Equal(t, []string{"app.example.com"}, analysis.Groups[0].FullDomains)
	assert.Equal(t, []string{"app"}, analysis.Groups[0].Subdomains)
	assert.False(t, analysis.Groups[0].IncludesApex)
}

func TestDomainGrouper_AnalyzeDomains_ApexDomain(t *testing.T) {
	grouper := NewDomainGrouper()
	analysis := grouper.AnalyzeDomains([]string{"example.com"})

	require.Len(t, analysis.Groups, 1)
	assert.Equal(t, "example.com", analysis.Groups[0].RootDomain)
	assert.True(t, analysis.Groups[0].IncludesApex)
	assert.Empty(t, analysis.Groups[0].Subdomains)
}

func TestDomainGrouper_AnalyzeDomains_MultipleSubdomains_WithDNS(t *testing.T) {
	grouper := NewDomainGrouper()
	grouper.DNSProviderAvailable = true
	grouper.PreferWildcard = true
	grouper.MinSubdomainsForWildcard = 2

	domains := []string{"app.example.com", "api.example.com", "www.example.com"}
	analysis := grouper.AnalyzeDomains(domains)

	require.Len(t, analysis.Groups, 1)
	group := analysis.Groups[0]

	assert.Equal(t, "example.com", group.RootDomain)
	assert.Equal(t, StrategyWildcard, group.Strategy)
	assert.Equal(t, "*.example.com", group.WildcardDomain)
	assert.True(t, analysis.DNSRequired)
	assert.Equal(t, 1, analysis.TotalCerts) // One wildcard covers all
}

func TestDomainGrouper_AnalyzeDomains_MultipleSubdomains_NoDNS(t *testing.T) {
	grouper := NewDomainGrouper()
	grouper.DNSProviderAvailable = false

	domains := []string{"app.example.com", "api.example.com", "www.example.com"}
	analysis := grouper.AnalyzeDomains(domains)

	require.Len(t, analysis.Groups, 1)
	group := analysis.Groups[0]

	assert.Equal(t, "example.com", group.RootDomain)
	assert.Equal(t, StrategySAN, group.Strategy) // Falls back to SAN without DNS
	assert.Empty(t, group.WildcardDomain)
	assert.False(t, analysis.DNSRequired)
}

func TestDomainGrouper_AnalyzeDomains_MultiLevelSubdomains(t *testing.T) {
	grouper := NewDomainGrouper()
	grouper.DNSProviderAvailable = true
	grouper.PreferWildcard = true

	// Multi-level subdomains shouldn't use wildcard (*.example.com doesn't cover a.b.example.com)
	domains := []string{"a.b.example.com", "c.d.example.com"}
	analysis := grouper.AnalyzeDomains(domains)

	require.Len(t, analysis.Groups, 1)
	group := analysis.Groups[0]

	assert.Equal(t, StrategySAN, group.Strategy) // Not wildcard due to multi-level
}

func TestDomainGrouper_AnalyzeDomains_MultipleDomains(t *testing.T) {
	grouper := NewDomainGrouper()
	grouper.DNSProviderAvailable = true
	grouper.PreferWildcard = true

	domains := []string{
		"app.example.com",
		"api.example.com",
		"www.other.io",
	}
	analysis := grouper.AnalyzeDomains(domains)

	require.Len(t, analysis.Groups, 2)

	// Find each group
	var exampleGroup, otherGroup *DomainGroup
	for _, g := range analysis.Groups {
		switch g.RootDomain {
		case "example.com":
			exampleGroup = g
		case "other.io":
			otherGroup = g
		}
	}

	require.NotNil(t, exampleGroup)
	require.NotNil(t, otherGroup)

	assert.Equal(t, StrategyWildcard, exampleGroup.Strategy)
	assert.Equal(t, StrategyIndividual, otherGroup.Strategy) // Only 1 subdomain
}

func TestDomainGrouper_AnalyzeDomains_ExplicitWildcard(t *testing.T) {
	grouper := NewDomainGrouper()

	domains := []string{"*.example.com"}
	analysis := grouper.AnalyzeDomains(domains)

	require.Len(t, analysis.Groups, 1)
	group := analysis.Groups[0]

	assert.Equal(t, StrategyWildcard, group.Strategy)
	assert.Equal(t, "*.example.com", group.WildcardDomain)
}

func TestDomainGrouper_AnalyzeDomains_ApexWithSubdomains(t *testing.T) {
	grouper := NewDomainGrouper()
	grouper.DNSProviderAvailable = true
	grouper.PreferWildcard = true

	domains := []string{"example.com", "app.example.com", "api.example.com"}
	analysis := grouper.AnalyzeDomains(domains)

	require.Len(t, analysis.Groups, 1)
	group := analysis.Groups[0]

	assert.True(t, group.IncludesApex)
	assert.Equal(t, StrategyWildcard, group.Strategy)

	// GetDomainsForCert should include both wildcard and apex
	cerDomains := group.GetDomainsForCert()
	assert.Contains(t, cerDomains, "*.example.com")
	assert.Contains(t, cerDomains, "example.com")
}

func TestDomainGroup_MatchesDomain(t *testing.T) {
	tests := []struct {
		name     string
		group    *DomainGroup
		domain   string
		expected bool
	}{
		{
			name: "exact match",
			group: &DomainGroup{
				FullDomains: []string{"app.example.com"},
			},
			domain:   "app.example.com",
			expected: true,
		},
		{
			name: "wildcard match - single level",
			group: &DomainGroup{
				Strategy:       StrategyWildcard,
				WildcardDomain: "*.example.com",
			},
			domain:   "app.example.com",
			expected: true,
		},
		{
			name: "wildcard no match - multi level",
			group: &DomainGroup{
				Strategy:       StrategyWildcard,
				WildcardDomain: "*.example.com",
			},
			domain:   "a.b.example.com",
			expected: false,
		},
		{
			name: "wildcard no match - different domain",
			group: &DomainGroup{
				Strategy:       StrategyWildcard,
				WildcardDomain: "*.example.com",
			},
			domain:   "app.other.com",
			expected: false,
		},
		{
			name: "apex match",
			group: &DomainGroup{
				RootDomain:   "example.com",
				IncludesApex: true,
			},
			domain:   "example.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.group.MatchesDomain(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDomainGroup_CertificateIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		group    *DomainGroup
		expected string
	}{
		{
			name: "wildcard",
			group: &DomainGroup{
				RootDomain: "example.com",
				Strategy:   StrategyWildcard,
			},
			expected: "wildcard:example.com",
		},
		{
			name: "SAN",
			group: &DomainGroup{
				FullDomains: []string{"app.example.com", "api.example.com"},
				Strategy:    StrategySAN,
			},
			expected: "san:api.example.com,app.example.com", // Sorted
		},
		{
			name: "individual",
			group: &DomainGroup{
				FullDomains: []string{"app.example.com"},
				Strategy:    StrategyIndividual,
			},
			expected: "single:app.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.group.CertificateIdentifier()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDomainAnalysis_SummaryStats(t *testing.T) {
	analysis := &DomainAnalysis{
		TotalDomains: 5,
		TotalCerts:   3,
		DNSRequired:  true,
		Groups: []*DomainGroup{
			{Strategy: StrategyWildcard},
			{Strategy: StrategySAN},
			{Strategy: StrategyIndividual, FullDomains: []string{"a.com", "b.com"}},
		},
	}

	stats := analysis.SummaryStats()

	assert.Equal(t, 5, stats["total_domains"])
	assert.Equal(t, 3, stats["total_certs"])
	assert.Equal(t, true, stats["dns_required"])
	assert.Equal(t, 1, stats["wildcard_certs"])
	assert.Equal(t, 1, stats["san_certs"])
	assert.Equal(t, 2, stats["individual_certs"])
	assert.Equal(t, 3, stats["groups"])
}
