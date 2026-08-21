package server

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/basecamp/kamal-proxy/internal/server/acme/providers"
)

// Per-zone DNS-01 provider selection.
//
// A fleet that terminates TLS for several wildcard zones often has those
// zones registered at different DNS hosts. The configuration maps zones to
// providers; this file builds one DNS-01 client per named provider (all on
// the same ACME account) and routes each order to the provider its zone
// names, with the single default provider answering for everything else.

// initDNSClients builds the DNS-01 clients the configuration names, on the
// primary account. Must be called with m.mu held.
func (m *SANCertManager) initDNSClients() error {
	def, zoned, err := m.buildDNSObtainers(m.user, m.config.Directory)
	if err != nil {
		return err
	}

	if len(zoned) > 0 {
		m.dnsObtainers = zoned
		slog.Info("Per-zone DNS-01 challenge solvers initialized",
			"zones", slices.Sorted(maps.Keys(m.selection.Zones)))
	}

	if def != nil {
		m.dnsObtainer = def
		slog.Info("DNS-01 challenge solver initialized", "provider", m.config.DNSProvider)
	}

	if m.dnsObtainer != nil || len(m.dnsObtainers) > 0 {
		m.grouper.DNSProviderAvailable = true
	}

	return nil
}

// buildDNSObtainers builds the DNS-01 clients the configuration names, on the
// given ACME identity — the primary account at boot, or a per-service
// directory's account when its bundle is built.
//
// The two configuration forms fail differently on a broken provider: an
// explicit zone mapping is explicit intent — silently continuing without its
// provider is the exact failure per-zone selection exists to remove — so it
// fails the caller outright. The default provider keeps its existing
// softness: with HTTP fallback on, a provider that cannot be constructed logs
// and leaves issuance on HTTP-01.
func (m *SANCertManager) buildDNSObtainers(user *acmeUser, directory string) (certObtainer, map[acme.ProviderName]certObtainer, error) {
	clients := map[acme.ProviderName]certObtainer{}

	for _, zone := range slices.Sorted(maps.Keys(m.selection.Zones)) {
		name := m.selection.Zones[zone]
		if _, ok := clients[name]; ok {
			continue
		}

		obtainer, err := m.newDNSObtainer(user, directory, name)
		if err != nil {
			return nil, nil, fmt.Errorf("DNS provider %q for zone %q: %w", name, zone, err)
		}
		clients[name] = obtainer
	}
	if len(clients) == 0 {
		clients = nil
	}

	var def certObtainer
	if m.config.DNSProvider != "" && m.config.DNSProvider != "none" {
		obtainer, err := m.newDNSObtainer(user, directory, m.config.DNSProvider)
		if err != nil {
			if !m.config.HTTPFallback {
				return nil, nil, fmt.Errorf("failed to create DNS provider %q: %w", m.config.DNSProvider, err)
			}
			slog.Warn("DNS provider not available, staying on HTTP-01",
				"provider", m.config.DNSProvider, "error", err)
		} else {
			def = obtainer
		}
	}

	return def, clients, nil
}

// newDNSObtainer builds a DNS-01 client for one provider on the given ACME
// identity and returns its certifier.
func (m *SANCertManager) newDNSObtainer(user *acmeUser, directory string, name acme.ProviderName) (certObtainer, error) {
	dnsProvider, err := providers.NewProvider(name)
	if err != nil {
		return nil, err
	}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = directory
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS-01 ACME client: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
		return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
	}

	return client.Certificate, nil
}

// providerPartitionKey identifies which DNS-01 solver would answer for a
// domain: "zone:<provider>" for a mapped zone, "" for the default path
// (the default provider, or HTTP-01 when none is configured). Two zones
// mapped to the same provider share a key — the boundary is the provider,
// not the zone — while the default never merges with a mapped partition,
// since "auto" hides which provider it resolved to. Safe without m.mu: the
// selection is immutable after construction.
func (m *SANCertManager) providerPartitionKey(domain string) string {
	provider, zone := m.selection.ProviderFor(domain)
	if zone == "" {
		return ""
	}
	return "zone:" + string(provider)
}

// splitByProviderZone partitions an identifier set by challenge solvability,
// so every partition is an order some solver can actually satisfy: no order
// spans DNS providers, and a wildcard order never includes an identifier
// outside the wildcard's zone. A wildcard forbids the order's HTTP-01
// fallback, so a foreign-zone rider would make the whole order unsatisfiable
// by construction — DNS-01 cannot answer for the foreign zone, HTTP-01 cannot
// answer for the wildcard (#108).
//
// Each wildcard anchors its own partition, keyed by its zone. Identifiers
// inside a wildcard's zone (equal or below on a label boundary — membership
// is the zone's, not the wildcard's single-label coverage) join it when the
// same provider answers for them, longest zone winning. A wildcard no DNS
// provider can solve is isolated alone, so its refusal at order time cannot
// drag down names that HTTP-01 could have satisfied. Everything else keeps
// its provider partition. Partitions keep first-appearance order, so a sorted
// input yields deterministic output.
func (m *SANCertManager) splitByProviderZone(domains []string) [][]string {
	anchors := m.wildcardAnchors(domains)
	if !m.selection.HasZones() && len(anchors) == 0 {
		return [][]string{domains}
	}

	keys := []string{}
	partitions := map[string][]string{}
	for _, domain := range domains {
		key := m.solvabilityPartitionKey(domain, anchors)
		if _, ok := partitions[key]; !ok {
			keys = append(keys, key)
		}
		partitions[key] = append(partitions[key], domain)
	}

	split := make([][]string, 0, len(keys))
	for _, key := range keys {
		split = append(split, partitions[key])
	}
	return split
}

// wildcardAnchor is a wildcard identifier's claim on a partition: the zone it
// anchors, the provider partition it lives in, and the key its members share.
// An unsolvable wildcard is a solo anchor — it attracts no members.
type wildcardAnchor struct {
	zone        string
	providerKey string
	key         string
	solvable    bool
}

// wildcardAnchors collects the partitions anchored by the batch's wildcard
// identifiers, longest zone first so nested zones resolve to the tightest
// enclosing wildcard.
func (m *SANCertManager) wildcardAnchors(domains []string) []wildcardAnchor {
	anchors := []wildcardAnchor{}
	seen := map[string]bool{}
	for _, domain := range domains {
		if !strings.HasPrefix(domain, "*.") {
			continue
		}
		zone := normalizeDomainName(domain[2:])
		if seen[zone] {
			continue
		}
		seen[zone] = true

		anchor := wildcardAnchor{zone: zone, providerKey: m.providerPartitionKey(domain)}
		if m.hasDNSProviderFor(domain) {
			anchor.key = "wildcard:" + zone + "|" + anchor.providerKey
			anchor.solvable = true
		} else {
			anchor.key = "unsolvable-wildcard:" + zone
		}
		anchors = append(anchors, anchor)
	}

	slices.SortStableFunc(anchors, func(a, b wildcardAnchor) int {
		return len(b.zone) - len(a.zone)
	})
	return anchors
}

// solvabilityPartitionKey keys one identifier: a wildcard keys by its own
// anchor; a concrete name joins the longest enclosing solvable wildcard zone
// whose provider also answers for it, else keeps its provider partition.
func (m *SANCertManager) solvabilityPartitionKey(domain string, anchors []wildcardAnchor) string {
	if strings.HasPrefix(domain, "*.") {
		zone := normalizeDomainName(domain[2:])
		for _, anchor := range anchors {
			if anchor.zone == zone {
				return anchor.key
			}
		}
	}

	providerKey := m.providerPartitionKey(domain)
	for _, anchor := range anchors {
		if anchor.solvable && anchor.providerKey == providerKey && zoneContains(anchor.zone, domain) {
			return anchor.key
		}
	}
	return providerKey
}

// zoneContains reports whether a domain sits inside a DNS zone: equal to it,
// or below it on a label boundary.
func zoneContains(zone, domain string) bool {
	candidate := normalizeDomainName(domain)
	return candidate == zone || strings.HasSuffix(candidate, "."+zone)
}

// normalizeDomainName lowercases a domain and strips any trailing dot, so
// identifiers compare in the same space as configured zones.
func normalizeDomainName(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// outsideWildcardZones returns the first identifier that sits outside every
// wildcard zone in an order, or "" when the order is zone-coherent. Batching
// splits by solvability before ordering, so a violation here means a caller
// bypassed the split.
func outsideWildcardZones(domains []string) string {
	zones := []string{}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			zones = append(zones, normalizeDomainName(domain[2:]))
		}
	}

	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			continue
		}
		covered := false
		for _, zone := range zones {
			if zoneContains(zone, domain) {
				covered = true
				break
			}
		}
		if !covered {
			return domain
		}
	}
	return ""
}

// orderObtainer resolves the one DNS obtainer answering for an order's
// domains on the primary identity. Nil with no error means no DNS provider
// covers them: HTTP-01 territory.
func (m *SANCertManager) orderObtainer(domains []string) (certObtainer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return orderObtainerFrom(m.selection, domains, m.dnsObtainer, m.dnsObtainers)
}

// orderObtainerFrom resolves the one DNS obtainer answering for an order's
// domains out of the given identity's solvers. Nil with no error means no DNS
// provider covers them: HTTP-01 territory. Batching splits before ordering,
// so an order spanning providers is an invariant violation, refused rather
// than half-answered.
func orderObtainerFrom(selection acme.ProviderSelection, domains []string, def certObtainer, zoned map[acme.ProviderName]certObtainer) (certObtainer, error) {
	var obtainer certObtainer
	key := ""
	for i, domain := range domains {
		domainObtainer, domainKey := resolveObtainerFrom(selection, domain, def, zoned)
		if i == 0 {
			obtainer, key = domainObtainer, domainKey
			continue
		}
		if domainKey != key {
			return nil, fmt.Errorf("%w: order %v spans DNS providers", ErrProvisioningFailed, domains)
		}
	}
	return obtainer, nil
}

// resolveObtainerFrom returns the obtainer and partition key for one domain
// out of the given identity's solvers.
func resolveObtainerFrom(selection acme.ProviderSelection, domain string, def certObtainer, zoned map[acme.ProviderName]certObtainer) (certObtainer, string) {
	provider, zone := selection.ProviderFor(domain)
	if zone != "" {
		return zoned[provider], "zone:" + string(provider)
	}
	return def, ""
}

// hasDNSProviderFor reports whether some DNS-01 obtainer would answer for a
// domain — a mapped zone's, or the default provider's.
func (m *SANCertManager) hasDNSProviderFor(domain string) bool {
	obtainer, err := m.orderObtainer([]string{domain})
	return err == nil && obtainer != nil
}
