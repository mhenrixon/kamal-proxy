package server

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
)

// Issuance strategy for the SAN certificate manager.
//
// One manager, one ACME account, two challenge types. Which one answers an
// order is decided here and nowhere else, so every issuance path -- the
// handshake-driven deploy path, the dynamic issuer, the renewer -- goes through
// the same allowlist and the same rate limit before it reaches a solver.

// obtainCertificate runs one ACME order under the configured strategy: DNS-01
// when a provider is configured, HTTP-01 otherwise, and HTTP-01 as a retry when
// DNS-01 fails and --acme-http-fallback allows it. A wildcard is DNS-01 only --
// no fallback can validate one -- so it is refused outright without a provider
// rather than handed to a solver that cannot answer.
//
// It deliberately does NOT take a rate limit token: callers hold one already,
// so that a queued order waits before it is assembled rather than after.
func (m *SANCertManager) obtainCertificate(request certificate.ObtainRequest) (*certificate.Resource, error) {
	m.mu.RLock()
	dnsObtainer := m.dnsObtainer
	httpObtainer := m.httpObtainer
	httpFallback := m.config.HTTPFallback
	m.mu.RUnlock()

	wildcard := containsWildcard(request.Domains)

	if dnsObtainer != nil {
		resource, err := dnsObtainer.Obtain(request)
		if err == nil {
			return resource, nil
		}

		if wildcard || !httpFallback || httpObtainer == nil {
			return nil, fmt.Errorf("DNS-01 issuance failed for %v: %w", request.Domains, err)
		}

		slog.Warn("DNS-01 issuance failed, retrying over HTTP-01",
			"domains", request.Domains, "error", err)
		return httpObtainer.Obtain(request)
	}

	if wildcard {
		return nil, fmt.Errorf("%w: %v needs a DNS-01 provider (--acme-dns-provider)",
			ErrProvisioningFailed, request.Domains)
	}

	if httpObtainer == nil {
		return nil, ErrManagerNotReady
	}

	return httpObtainer.Obtain(request)
}

// planIssuanceDomains rewrites a batch of deploy-registered hosts into the
// identifier set to actually order. With a DNS provider and
// --acme-prefer-wildcard, sibling single-level subdomains under one root
// collapse into "*.root" -- plus the apex, which a wildcard does not cover.
// Without a provider the batch is returned unchanged, since HTTP-01 cannot
// validate a wildcard.
//
// It is applied only to deploy-registered hosts. Dynamic domains from a
// tls-domains-source are tenant-owned names spread across unrelated roots; the
// proxy holds no DNS control over them, so collapsing them into a wildcard
// would order something it could never validate.
func (m *SANCertManager) planIssuanceDomains(domains []string) []string {
	m.mu.RLock()
	grouper := m.grouper
	dnsAvailable := m.dnsObtainer != nil
	m.mu.RUnlock()

	if !dnsAvailable || grouper == nil {
		return append([]string{}, domains...)
	}

	planned := []string{}
	for _, group := range grouper.AnalyzeDomains(domains).Groups {
		planned = append(planned, group.GetDomainsForCert()...)
	}

	if len(planned) == 0 {
		return append([]string{}, domains...)
	}

	return planned
}

// restorePending returns a failed batch's domains to the pending set so a later
// handshake or poll can retry them.
func (m *SANCertManager) restorePending(domains []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, domain := range domains {
		if _, ok := m.pendingDomains[domain]; !ok {
			m.pendingDomains[domain] = ""
		}
	}
}

// certIDCovering returns the identifier of the certificate that serves a
// domain: an exact match, or the single-level wildcard one label above it.
// Callers must hold m.mu.
func (m *SANCertManager) certIDCovering(domain string) string {
	if certID, ok := m.domainToCert[domain]; ok {
		return certID
	}

	if parent, ok := wildcardParent(domain); ok {
		return m.domainToCert[parent]
	}

	return ""
}

// wildcardParent returns the wildcard pattern that would cover a domain, e.g.
// "*.example.com" for "app.example.com". A bare label or a trailing dot has
// none.
func wildcardParent(domain string) (string, bool) {
	dot := strings.IndexByte(domain, '.')
	if dot <= 0 || dot == len(domain)-1 {
		return "", false
	}

	return "*." + domain[dot+1:], true
}

// matchesWildcard reports whether a wildcard pattern covers a domain. ACME
// wildcards match exactly one label, and never the apex.
func matchesWildcard(pattern, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	parent, ok := wildcardParent(domain)
	return ok && parent == pattern
}

func sortedCopy(domains []string) []string {
	sorted := append([]string{}, domains...)
	slices.Sort(sorted)
	return sorted
}

func containsWildcard(domains []string) bool {
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			return true
		}
	}
	return false
}
