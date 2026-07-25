package server

import (
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// CertStrategy defines how certificates should be provisioned for a domain group
type CertStrategy int

const (
	// StrategyWildcard uses a wildcard certificate (*.example.com)
	StrategyWildcard CertStrategy = iota
	// StrategySAN uses a single certificate with multiple Subject Alternative Names
	StrategySAN
	// StrategyIndividual uses individual certificates for each domain
	StrategyIndividual
)

func (s CertStrategy) String() string {
	switch s {
	case StrategyWildcard:
		return "wildcard"
	case StrategySAN:
		return "san"
	case StrategyIndividual:
		return "individual"
	default:
		return "unknown"
	}
}

// DomainGroup represents a group of domains that can share a certificate
type DomainGroup struct {
	// RootDomain is the registrable domain (e.g., "example.com")
	RootDomain string
	// Subdomains are the subdomain parts (e.g., ["app", "api", "www"])
	Subdomains []string
	// FullDomains are the complete domain names
	FullDomains []string
	// IncludesApex indicates if the apex domain (example.com) is included
	IncludesApex bool
	// Strategy is the recommended certificate strategy
	Strategy CertStrategy
	// WildcardDomain is the wildcard domain if using wildcard strategy
	WildcardDomain string
}

// DomainAnalysis contains the result of analyzing a set of domains
type DomainAnalysis struct {
	Groups          []*DomainGroup
	DNSRequired     bool // True if any group requires DNS-01 (wildcards)
	TotalDomains    int
	TotalCerts      int
	WildcardDomains []string // List of wildcard domains to provision
}

// DomainGrouper analyzes domains and groups them for efficient certificate provisioning
type DomainGrouper struct {
	// MinSubdomainsForWildcard is the minimum number of subdomains to use wildcard strategy
	MinSubdomainsForWildcard int
	// PreferWildcard indicates whether to prefer wildcard certificates when possible
	PreferWildcard bool
	// DNSProviderAvailable indicates whether DNS-01 challenge is available
	DNSProviderAvailable bool
}

// NewDomainGrouper creates a new DomainGrouper with default settings
func NewDomainGrouper() *DomainGrouper {
	return &DomainGrouper{
		MinSubdomainsForWildcard: 2, // Use wildcard if 2+ subdomains
		PreferWildcard:           true,
		DNSProviderAvailable:     false,
	}
}

// AnalyzeDomains analyzes a list of domains and groups them for efficient certificate provisioning
func (g *DomainGrouper) AnalyzeDomains(domains []string) *DomainAnalysis {
	if len(domains) == 0 {
		return &DomainAnalysis{}
	}

	// Group domains by their root domain
	rootGroups := make(map[string]*DomainGroup)

	for _, domain := range domains {
		// Skip wildcard domains for now, handle them specially
		if strings.HasPrefix(domain, "*.") {
			// Explicit wildcard requested
			rootDomain := domain[2:] // Remove "*."
			group, ok := rootGroups[rootDomain]
			if !ok {
				group = &DomainGroup{
					RootDomain: rootDomain,
				}
				rootGroups[rootDomain] = group
			}
			group.Strategy = StrategyWildcard
			group.WildcardDomain = domain
			continue
		}

		// Get the registrable domain (e.g., "example.com" from "app.example.com")
		rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			// If we can't parse it, treat it as its own group
			rootDomain = domain
		}

		group, ok := rootGroups[rootDomain]
		if !ok {
			group = &DomainGroup{
				RootDomain: rootDomain,
			}
			rootGroups[rootDomain] = group
		}

		group.FullDomains = append(group.FullDomains, domain)

		// Determine if this is the apex domain or a subdomain
		if domain == rootDomain {
			group.IncludesApex = true
		} else {
			// Extract subdomain part
			subdomain := strings.TrimSuffix(domain, "."+rootDomain)
			group.Subdomains = append(group.Subdomains, subdomain)
		}
	}

	// Determine strategy for each group
	analysis := &DomainAnalysis{
		TotalDomains: len(domains),
	}

	for _, group := range rootGroups {
		g.determineStrategy(group)
		analysis.Groups = append(analysis.Groups, group)

		if group.Strategy == StrategyWildcard {
			analysis.DNSRequired = true
			analysis.WildcardDomains = append(analysis.WildcardDomains, group.WildcardDomain)
			analysis.TotalCerts++
		} else {
			analysis.TotalCerts += len(group.FullDomains)
		}
	}

	// Sort groups by root domain for consistent ordering
	sort.Slice(analysis.Groups, func(i, j int) bool {
		return analysis.Groups[i].RootDomain < analysis.Groups[j].RootDomain
	})

	return analysis
}

// determineStrategy determines the certificate strategy for a domain group
func (g *DomainGrouper) determineStrategy(group *DomainGroup) {
	// If wildcard was explicitly requested, use it
	if group.WildcardDomain != "" {
		group.Strategy = StrategyWildcard
		return
	}

	// Check if all subdomains are single-level (e.g., "app" not "a.b")
	allSingleLevel := true
	for _, sub := range group.Subdomains {
		if strings.Contains(sub, ".") {
			allSingleLevel = false
			break
		}
	}

	subdomainCount := len(group.Subdomains)

	// Determine strategy based on configuration and subdomain characteristics
	if g.DNSProviderAvailable && g.PreferWildcard && allSingleLevel && subdomainCount >= g.MinSubdomainsForWildcard {
		group.Strategy = StrategyWildcard
		group.WildcardDomain = "*." + group.RootDomain

		// If apex is included, we need to provision both wildcard and apex
		// Wildcard doesn't cover apex domain
		return
	}

	// If we have a few domains that can be grouped, use SAN certificate
	if len(group.FullDomains) >= 2 && len(group.FullDomains) <= 100 {
		group.Strategy = StrategySAN
		return
	}

	// Default to individual certificates
	group.Strategy = StrategyIndividual
}

// GetDomainsForCert returns the domains that should be included in a certificate
// based on the group's strategy
func (group *DomainGroup) GetDomainsForCert() []string {
	switch group.Strategy {
	case StrategyWildcard:
		domains := []string{group.WildcardDomain}
		// Always include apex domain with wildcard since wildcard doesn't cover it
		if group.IncludesApex {
			domains = append(domains, group.RootDomain)
		}
		return domains

	case StrategySAN:
		// Return all domains for a single SAN certificate
		return group.FullDomains

	case StrategyIndividual:
		// Each domain gets its own certificate
		return group.FullDomains

	default:
		return group.FullDomains
	}
}

// MatchesDomain checks if a domain is covered by this group
func (group *DomainGroup) MatchesDomain(domain string) bool {
	// Check explicit match
	for _, d := range group.FullDomains {
		if d == domain {
			return true
		}
	}

	// Check wildcard match
	if group.Strategy == StrategyWildcard && group.WildcardDomain != "" {
		wildcardSuffix := group.WildcardDomain[1:] // Remove "*", keep ".example.com"
		if strings.HasSuffix(domain, wildcardSuffix) {
			// Check it's a single level subdomain (wildcard doesn't match multi-level)
			prefix := strings.TrimSuffix(domain, wildcardSuffix)
			if !strings.Contains(prefix, ".") && prefix != "" {
				return true
			}
		}
	}

	// Check apex match
	if group.IncludesApex && domain == group.RootDomain {
		return true
	}

	return false
}

// CertificateIdentifier returns a unique identifier for the certificate this group will use
func (group *DomainGroup) CertificateIdentifier() string {
	switch group.Strategy {
	case StrategyWildcard:
		return "wildcard:" + group.RootDomain
	case StrategySAN:
		// Use a consistent identifier based on sorted domains
		domains := make([]string, len(group.FullDomains))
		copy(domains, group.FullDomains)
		sort.Strings(domains)
		return "san:" + strings.Join(domains, ",")
	case StrategyIndividual:
		// For individual strategy, caller should iterate over FullDomains
		if len(group.FullDomains) > 0 {
			return "single:" + group.FullDomains[0]
		}
		return "single:" + group.RootDomain
	default:
		return "unknown:" + group.RootDomain
	}
}

// SummaryStats returns summary statistics for the domain analysis
func (a *DomainAnalysis) SummaryStats() map[string]interface{} {
	wildcardCount := 0
	sanCount := 0
	individualCount := 0

	for _, group := range a.Groups {
		switch group.Strategy {
		case StrategyWildcard:
			wildcardCount++
		case StrategySAN:
			sanCount++
		case StrategyIndividual:
			individualCount += len(group.FullDomains)
		}
	}

	return map[string]interface{}{
		"total_domains":    a.TotalDomains,
		"total_certs":      a.TotalCerts,
		"dns_required":     a.DNSRequired,
		"wildcard_certs":   wildcardCount,
		"san_certs":        sanCount,
		"individual_certs": individualCount,
		"groups":           len(a.Groups),
	}
}
