package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

// testZonedManager returns a ready manager with per-zone DNS provider
// mappings. Like testSANCertManager, it has no ACME client; tests wire fake
// obtainers instead.
func testZonedManager(t testing.TB, defaultProvider acme.ProviderName, zones map[string]acme.ProviderName) *SANCertManager {
	t.Helper()

	tmpDir := t.TempDir()
	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:            "test@example.com",
		Directory:        LetsEncryptStaging,
		CachePath:        filepath.Join(tmpDir, "certs"),
		StatePath:        filepath.Join(tmpDir, "acme.state"),
		DNSProvider:      defaultProvider,
		DNSProviderZones: zones,
	})
	require.NoError(t, err)

	manager.ready = true
	return manager
}

func TestSANCertManager_SplitByProviderZone(t *testing.T) {
	manager := testZonedManager(t, acme.ProviderVultr, map[string]acme.ProviderName{
		"platform.example": acme.ProviderCloudflare,
		"legacy.example":   acme.ProviderHetzner,
	})

	partitions := manager.splitByProviderZone([]string{
		"a.platform.example", "b.legacy.example", "c.platform.example", "other.net",
	})

	require.Len(t, partitions, 3)
	assert.Equal(t, []string{"a.platform.example", "c.platform.example"}, partitions[0])
	assert.Equal(t, []string{"b.legacy.example"}, partitions[1])
	assert.Equal(t, []string{"other.net"}, partitions[2])
}

// Two zones at the same DNS host can share an order: the boundary is the
// provider, not the zone.
func TestSANCertManager_SplitByProviderZone_SameProviderZonesShareAPartition(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"platform.example": acme.ProviderCloudflare,
		"legacy.example":   acme.ProviderCloudflare,
	})

	partitions := manager.splitByProviderZone([]string{"a.platform.example", "b.legacy.example"})

	require.Len(t, partitions, 1)
	assert.Equal(t, []string{"a.platform.example", "b.legacy.example"}, partitions[0])
}

func TestSANCertManager_SplitByProviderZone_NoZonesKeepsOnePartition(t *testing.T) {
	manager := testSANCertManager(t)

	partitions := manager.splitByProviderZone([]string{"a.example.com", "b.example.net"})

	require.Len(t, partitions, 1)
}

// A mapping is explicit intent: silently continuing without its provider is
// the exact failure this feature exists to remove, so a broken mapping fails
// the boot even when HTTP fallback would soften the default provider.
func TestSANCertManager_InitDNSClients_MappedProviderWithoutCredentialsIsFatal(t *testing.T) {
	tmpDir := t.TempDir()
	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:            "test@example.com",
		Directory:        LetsEncryptStaging,
		CachePath:        filepath.Join(tmpDir, "certs"),
		DNSProviderZones: map[string]acme.ProviderName{"platform.example": acme.ProviderCloudflare},
		HTTPFallback:     true,
	})
	require.NoError(t, err)

	err = manager.initDNSClients()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "platform.example")
	assert.ErrorIs(t, err, acme.ErrMissingCredentials)
}

// The default provider keeps its existing softness: with HTTP fallback on, a
// provider that cannot be constructed logs and leaves issuance on HTTP-01.
func TestSANCertManager_InitDNSClients_DefaultProviderFallbackStaysSoft(t *testing.T) {
	tmpDir := t.TempDir()
	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:        "test@example.com",
		Directory:    LetsEncryptStaging,
		CachePath:    filepath.Join(tmpDir, "certs"),
		DNSProvider:  acme.ProviderCloudflare,
		HTTPFallback: true,
	})
	require.NoError(t, err)

	require.NoError(t, manager.initDNSClients())
	assert.Nil(t, manager.dnsObtainer)
}

func TestSANCertManager_ObtainCertificate_RoutesOrderByZone(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	zoneObtainer := successfulObtainer(t)
	httpObtainer := successfulObtainer(t)
	manager.dnsObtainers = map[acme.ProviderName]certObtainer{acme.ProviderHetzner: zoneObtainer}
	manager.httpObtainer = httpObtainer

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"www.legacy.example"}})
	require.NoError(t, err)
	assert.Len(t, zoneObtainer.Calls(), 1)
	assert.Empty(t, httpObtainer.Calls())

	// A domain no zone matches has no default provider here: HTTP-01 answers.
	_, err = manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"other.net"}})
	require.NoError(t, err)
	assert.Len(t, zoneObtainer.Calls(), 1)
	assert.Len(t, httpObtainer.Calls(), 1)
}

func TestSANCertManager_ObtainCertificate_WildcardForMappedZoneUsesItsProvider(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	zoneObtainer := successfulObtainer(t)
	manager.dnsObtainers = map[acme.ProviderName]certObtainer{acme.ProviderHetzner: zoneObtainer}
	manager.httpObtainer = successfulObtainer(t)

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"*.legacy.example"}})
	require.NoError(t, err)
	require.Len(t, zoneObtainer.Calls(), 1)
	assert.Equal(t, []string{"*.legacy.example"}, zoneObtainer.Calls()[0].Domains)
}

func TestSANCertManager_ObtainCertificate_WildcardWithoutProviderStillRefused(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	manager.dnsObtainers = map[acme.ProviderName]certObtainer{acme.ProviderHetzner: successfulObtainer(t)}
	httpObtainer := successfulObtainer(t)
	manager.httpObtainer = httpObtainer

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"*.other.net"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--acme-dns-provider")
	assert.Empty(t, httpObtainer.Calls(), "HTTP-01 cannot validate a wildcard")
}

// Batching splits before ordering, so an order spanning providers is an
// invariant violation, refused rather than half-answered.
func TestSANCertManager_ObtainCertificate_RefusesOrderSpanningProviders(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	zoneObtainer := successfulObtainer(t)
	manager.dnsObtainers = map[acme.ProviderName]certObtainer{acme.ProviderHetzner: zoneObtainer}
	httpObtainer := successfulObtainer(t)
	manager.httpObtainer = httpObtainer

	_, err := manager.obtainCertificate(certificate.ObtainRequest{
		Domains: []string{"www.legacy.example", "other.net"},
	})
	require.Error(t, err)
	assert.Empty(t, zoneObtainer.Calls())
	assert.Empty(t, httpObtainer.Calls())
}

func TestSANCertManager_ObtainCertificate_ZoneOrderFallsBackToHTTPWhenAllowed(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	manager.config.HTTPFallback = true
	failing := &fakeObtainer{respond: func(certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, assert.AnError
	}}
	httpObtainer := successfulObtainer(t)
	manager.dnsObtainers = map[acme.ProviderName]certObtainer{acme.ProviderHetzner: failing}
	manager.httpObtainer = httpObtainer

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"www.legacy.example"}})
	require.NoError(t, err)
	assert.Len(t, failing.Calls(), 1)
	assert.Len(t, httpObtainer.Calls(), 1)
}

// The handshake is waiting, so a pending batch that spans providers narrows
// to the requested domain's partition; the rest return to pending for their
// own handshake or poll.
func TestSANCertManager_ProvisionCertificate_NarrowsBatchToOnePartition(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	zoneObtainer := successfulObtainer(t)
	httpObtainer := successfulObtainer(t)
	manager.dnsObtainers = map[acme.ProviderName]certObtainer{acme.ProviderHetzner: zoneObtainer}
	manager.httpObtainer = httpObtainer

	manager.pendingDomains["shop.legacy.example"] = "service1"
	manager.pendingDomains["other.net"] = "service1"

	cert, err := manager.provisionCertificate(context.Background(), "www.legacy.example")
	require.NoError(t, err)
	require.NotNil(t, cert)

	calls := zoneObtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"shop.legacy.example", "www.legacy.example"}, calls[0].Domains)
	assert.Empty(t, httpObtainer.Calls(), "the deferred partition must not be ordered on the handshake's clock")

	manager.mu.RLock()
	_, stillPending := manager.pendingDomains["other.net"]
	manager.mu.RUnlock()
	assert.True(t, stillPending, "the deferred partition's domains return to pending")
}

// Auto-collapse to a wildcard only helps when some DNS provider can validate
// it; a zone left to HTTP-01 keeps its concrete names.
func TestSANCertManager_PlanIssuanceDomains_CollapsesOnlyZonesWithAProvider(t *testing.T) {
	tmpDir := t.TempDir()
	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:            "test@example.com",
		Directory:        LetsEncryptStaging,
		CachePath:        filepath.Join(tmpDir, "certs"),
		DNSProviderZones: map[string]acme.ProviderName{"legacy.example": acme.ProviderHetzner},
		PreferWildcard:   true,
	})
	require.NoError(t, err)
	manager.ready = true
	manager.dnsObtainers = map[acme.ProviderName]certObtainer{acme.ProviderHetzner: successfulObtainer(t)}
	manager.grouper.DNSProviderAvailable = true

	planned := manager.planIssuanceDomains([]string{
		"a.legacy.example", "b.legacy.example",
		"a.other.net", "b.other.net",
	})

	assert.Contains(t, planned, "*.legacy.example")
	assert.NotContains(t, planned, "*.other.net")
	assert.Contains(t, planned, "a.other.net")
	assert.Contains(t, planned, "b.other.net")
}

// A dynamic-domain batch never spans providers either: the issuer groups by
// partition when assembling it.
func TestDomainIssuer_NextBatch_NeverSpansProviderZones(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	issuer := newDomainIssuer(manager, newDomainQuarantine(), domainIssuerConfig{
		Obtainer:  successfulObtainer(t),
		BatchSize: func(service string) int { return 10 },
	})
	manager.SetDynamicDomains("service1", []string{"a.legacy.example", "b.other.net", "c.legacy.example"})

	issuer.Request("a.legacy.example", "service1")
	issuer.Request("b.other.net", "service1")
	issuer.Request("c.legacy.example", "service1")

	batch := issuer.nextBatch()
	domains := []string{}
	for _, request := range batch {
		domains = append(domains, request.domain)
	}
	assert.ElementsMatch(t, []string{"a.legacy.example", "c.legacy.example"}, domains)

	batch = issuer.nextBatch()
	require.Len(t, batch, 1)
	assert.Equal(t, "b.other.net", batch[0].domain)
}

// A certificate issued before mappings existed can span provider zones; its
// renewal splits along provider boundaries instead of failing.
func TestCertRenewer_SplitsMixedZoneCertificateAcrossProviders(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	manager.SetDynamicDomains("service1", []string{"tenant.legacy.example", "tenant.other.net"})
	old := adoptTestCert(t, manager, []string{"tenant.legacy.example", "tenant.other.net"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	obtainer := successfulObtainer(t)
	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 2)
	assert.Equal(t, []string{"tenant.legacy.example"}, calls[0].Domains)
	assert.Equal(t, []string{"tenant.other.net"}, calls[1].Domains)

	// ARI: a certificate is replaced once; the marker rides the first order.
	assert.NotEmpty(t, calls[0].ReplacesCertID)
	assert.Empty(t, calls[1].ReplacesCertID)

	// The spanning certificate is gone, replaced by one per partition.
	certs := manager.ManagedCertificates()
	require.Len(t, certs, 2)
	for _, cert := range certs {
		assert.NotEqual(t, old.Identifier, cert.Identifier)
	}
}

func TestCertRenewer_MixedZoneSplitKeepsOldCertWhenAPartitionFails(t *testing.T) {
	manager := testZonedManager(t, "", map[string]acme.ProviderName{
		"legacy.example": acme.ProviderHetzner,
	})
	manager.SetDynamicDomains("service1", []string{"tenant.legacy.example", "tenant.other.net"})
	old := adoptTestCert(t, manager, []string{"tenant.legacy.example", "tenant.other.net"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		if request.Domains[0] == "tenant.other.net" {
			return nil, assert.AnError
		}
		return testCertResource(t, request.Domains, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)), nil
	}}
	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	require.Len(t, obtainer.Calls(), 2)

	// The failed partition's domain keeps serving the old certificate.
	identifiers := []string{}
	for _, cert := range manager.ManagedCertificates() {
		identifiers = append(identifiers, cert.Identifier)
	}
	assert.Contains(t, identifiers, old.Identifier)
	assert.Equal(t, old.Identifier, manager.certIDForDomain("tenant.other.net"))
	assert.NotEqual(t, old.Identifier, manager.certIDForDomain("tenant.legacy.example"))
}
