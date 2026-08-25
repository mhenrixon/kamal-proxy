package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acmeconfig "github.com/basecamp/kamal-proxy/internal/server/acme"
)

func testGuardedManager(t testing.TB, obtainer certObtainer) (*SANCertManager, *domainQuarantine) {
	t.Helper()

	manager := testSANCertManager(t)
	manager.httpObtainer = obtainer
	quarantine := newDomainQuarantine()
	return manager, quarantine
}

func pendingDomainsOf(manager *SANCertManager) []string {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	domains := []string{}
	for domain := range manager.pendingDomains {
		domains = append(domains, domain)
	}
	return domains
}

func TestBatchGuard_QuarantinedBatchMateIsSkippedButStaysPending(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(nil, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("bad.example.com", "service1"))
	quarantine.RecordFailure("bad.example.com", quarantineACME)

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"app.example.com"}, calls[0].Domains)

	// The quarantined mate keeps its pending slot for a later batch.
	assert.Contains(t, pendingDomainsOf(manager), "bad.example.com")
}

func TestBatchGuard_UnreachableBatchMateIsQuarantinedWithoutBurningAnOrder(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error {
		if domain == "dead.example.com" {
			return errors.New("does not route here")
		}
		return nil
	}, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("dead.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"app.example.com"}, calls[0].Domains)

	assert.True(t, quarantine.IsQuarantined("dead.example.com"))
	assert.Contains(t, pendingDomainsOf(manager), "dead.example.com")
}

// A domain whose order will be answered by DNS-01 does not have to route
// anywhere. Probing it over HTTP and holding it back when the probe fails is
// exactly backwards: DNS-01 is what makes issuing before a cutover safe.
func TestBatchGuard_DNSSolvableBatchMateIsNotProbed(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.dnsObtainers = map[acmeconfig.ProviderName]certObtainer{"cloudflare": obtainer}
	manager.selection = acmeconfig.ProviderSelection{Zones: map[string]acmeconfig.ProviderName{"enode.site": "cloudflare"}}

	probed := []string{}
	manager.SetIssuanceGuard(func(domain string) error {
		probed = append(probed, domain)
		return errors.New("does not route here")
	}, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("enode.site", "service1"))
	require.NoError(t, manager.RegisterDomain("www.enode.site", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "enode.site")
	require.NoError(t, err)

	assert.Empty(t, probed, "a DNS-01 zone must never be HTTP-probed")

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.ElementsMatch(t, []string{"enode.site", "www.enode.site"}, calls[0].Domains,
		"the mate belongs in the order: DNS-01 can validate it wherever it points")
	assert.False(t, quarantine.IsQuarantined("www.enode.site"))
}

// The same manager, for a zone with no DNS provider, must keep probing.
func TestBatchGuard_HTTPOnlyBatchMateIsStillProbedAlongsideADNSZone(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.dnsObtainers = map[acmeconfig.ProviderName]certObtainer{"cloudflare": obtainer}
	manager.selection = acmeconfig.ProviderSelection{Zones: map[string]acmeconfig.ProviderName{"enode.site": "cloudflare"}}

	probed := []string{}
	manager.SetIssuanceGuard(func(domain string) error {
		probed = append(probed, domain)
		if domain == "dead.example.com" {
			return errors.New("does not route here")
		}
		return nil
	}, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("dead.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	// Both are HTTP-01, so both are probed: the trigger by the gate, the mate
	// by the batch filter. Neither rides on the DNS-01 zone's exemption.
	assert.ElementsMatch(t, []string{"app.example.com", "dead.example.com"}, probed)
	assert.True(t, quarantine.IsQuarantined("dead.example.com"))
}

func TestBatchGuard_ExpiringBatchMateIsProbedAndExcludedWhenUnreachable(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error {
		if domain == "dead.example.com" {
			return errors.New("does not route here")
		}
		return nil
	}, quarantine, nil)

	// dead.example.com held a certificate once, but it is expiring and its
	// DNS moved away — having been issued before must not exempt it from the
	// probe, or it poisons the trigger's order.
	adoptTestCert(t, manager, []string{"dead.example.com"},
		time.Now().Add(-89*24*time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, manager.RegisterDomain("dead.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"app.example.com"}, calls[0].Domains)
	assert.True(t, quarantine.IsQuarantined("dead.example.com"))
}

func TestBatchGuard_SuccessfulBatchClearsQuarantineHistory(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(nil, quarantine, nil)

	// The trigger carries failure history; a successful order must wipe it,
	// or its next failure starts higher up the backoff ladder.
	quarantine.RecordFailure("app.example.com", quarantineACME)
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	assert.Equal(t, 0, quarantine.Len())
}

func TestBatchGuard_MutationsNotifyChangeForPersistence(t *testing.T) {
	failing := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, fmt.Errorf("error: one or more domains had a problem:\nbad.example.com: acme: error presenting token")
	}}
	manager, quarantine := testGuardedManager(t, failing)

	changes := 0
	manager.SetIssuanceGuard(nil, quarantine, func() { changes++ })

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("bad.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)
	assert.Greater(t, changes, 0, "quarantining a culprit must notify for persistence")
}

func TestBatchGuard_QuarantinedDomainsDoNotConsumeBatchSlots(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(nil, quarantine, nil)

	// More quarantined hosts than a batch holds: the eligible mate must still
	// find a slot instead of the quarantined ones filling the batch first.
	for i := 0; i < MaxSANsPerCertificate+10; i++ {
		domain := fmt.Sprintf("quarantined-%d.example.com", i)
		require.NoError(t, manager.RegisterDomain(domain, "service1"))
		quarantine.RecordFailure(domain, quarantineACME)
	}
	require.NoError(t, manager.RegisterDomain("ok.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.ElementsMatch(t, []string{"app.example.com", "ok.example.com"}, calls[0].Domains)
}

// The trigger is still never filtered out of its own batch — filterBatchMates
// only ever considers the mates. What changed is upstream of it: the trigger
// is probed before the order, so a stale hold no longer decides its fate and
// an unreachable one no longer spends an order. Here the probe passes, so a
// prior hold is irrelevant and the handshake gets its certificate.
func TestBatchGuard_TriggerDomainIsNeverDroppedFromItsOwnBatch(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine, nil)
	quarantine.RecordFailure("app.example.com", quarantineACME)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"app.example.com"}, calls[0].Domains)

	// A passing probe is proof the hold was stale; it must not survive.
	assert.False(t, quarantine.IsQuarantined("app.example.com"))
}

// The defect this issue exists to fix: before a DNS cutover the domain still
// points at the old server, so an ACME order cannot succeed — but any
// handshake carrying that SNI spent one anyway. Five in an hour trips Let's
// Encrypt's failed-authorization limit, and the resulting hold is what delays
// the certificate at the actual cutover.
func TestBatchGuard_UnreachableTriggerIsRefusedWithoutBurningAnOrder(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error {
		return errors.New("does not route here")
	}, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.ErrorIs(t, err, ErrCertNotFound)

	assert.Empty(t, obtainer.Calls(), "no ACME order may be spent on a domain that cannot answer")

	// Held on the gentle ladder: no order was spent, so the first retry is soon.
	assert.True(t, quarantine.IsQuarantined("app.example.com"))
	assert.Equal(t, quarantinePreflight, quarantine.Snapshot()["app.example.com"].Kind)
}

// A held domain that starts routing here again gets its certificate on the
// very next handshake — the probe, not the ladder, is what governs.
func TestBatchGuard_ReachableTriggerProvisionsDespiteAStaleHold(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine, nil)

	// Four prior failures: deep on the ladder, held for 24 hours.
	for range 4 {
		quarantine.RecordFailure("app.example.com", quarantinePreflight)
	}
	require.True(t, quarantine.IsQuarantined("app.example.com"))

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)
	assert.Len(t, obtainer.Calls(), 1)
	assert.False(t, quarantine.IsQuarantined("app.example.com"))
}

// A DNS-01 trigger is never probed: its order does not depend on where it
// points, which is the whole reason to issue before a cutover.
func TestBatchGuard_DNSSolvableTriggerIsNotProbed(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.dnsObtainers = map[acmeconfig.ProviderName]certObtainer{"cloudflare": obtainer}
	manager.selection = acmeconfig.ProviderSelection{Zones: map[string]acmeconfig.ProviderName{"enode.site": "cloudflare"}}

	probed := 0
	manager.SetIssuanceGuard(func(domain string) error {
		probed++
		return errors.New("does not route here")
	}, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("enode.site", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "enode.site")
	require.NoError(t, err)

	assert.Zero(t, probed)
	assert.Len(t, obtainer.Calls(), 1)
}

// With no guard installed there is nothing to probe with, and behaviour is
// exactly as it was before the gate existed.
func TestBatchGuard_TriggerIsUngatedWhenNoProbeIsInstalled(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(nil, quarantine, nil)
	quarantine.RecordFailure("app.example.com", quarantineACME)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)
	assert.Len(t, obtainer.Calls(), 1)
}

func TestBatchGuard_QuarantinesCulpritsAndRestoresSurvivorsOnFailure(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, fmt.Errorf("error: one or more domains had a problem:\nbad.example.com: acme: error presenting token")
	}}
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(nil, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("bad.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)

	assert.True(t, quarantine.IsQuarantined("bad.example.com"))
	assert.False(t, quarantine.IsQuarantined("app.example.com"))

	// The survivor returns to pending for the next handshake; the culprit
	// waits out its quarantine instead.
	pending := pendingDomainsOf(manager)
	assert.Contains(t, pending, "app.example.com")
	assert.NotContains(t, pending, "bad.example.com")
}

func TestBatchGuard_UnattributableFailureRestoresEverythingUnquarantined(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, errors.New("acme: internal error")
	}}
	manager, quarantine := testGuardedManager(t, obtainer)
	// A generic ACME outage must not push deploy-registered hosts onto the
	// quarantine ladder; the probe passing everyone proves no culprit.
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("other.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)

	assert.Equal(t, 0, quarantine.Len())
	pending := pendingDomainsOf(manager)
	assert.Contains(t, pending, "app.example.com")
	assert.Contains(t, pending, "other.example.com")
}

func TestBatchGuard_RateLimitedIdentifierIsHeldAndSurvivorsRestored(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, rateLimitedProblem(`too many failed authorizations (5) for "limited.example.com", ` +
			`retry after 2100-01-01 00:00:00 UTC: see docs`)
	}}
	manager, quarantine := testGuardedManager(t, obtainer)
	// The probe passes everyone — attribution must come from the error alone.
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("limited.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)

	assert.True(t, quarantine.IsQuarantined("limited.example.com"))
	assert.False(t, quarantine.IsQuarantined("app.example.com"))
	snapshot := quarantine.Snapshot()
	expectedHold := time.Date(2100, 1, 1, 0, 1, 0, 0, time.UTC)
	assert.True(t, snapshot["limited.example.com"].Until.Equal(expectedHold),
		"hold must honor the advertised retry time, got %v", snapshot["limited.example.com"].Until)

	// The survivor returns to pending for the next handshake; the held
	// identifier waits out its advertised window instead.
	pending := pendingDomainsOf(manager)
	assert.Contains(t, pending, "app.example.com")
	assert.NotContains(t, pending, "limited.example.com")
}

func TestBatchGuard_UnnamedRateLimitWithRetryTimeHoldsWholeBatch(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, rateLimitedProblem(`too many new orders recently, retry after 2100-01-01 00:00:00 UTC: see docs`)
	}}
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("other.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)

	// An account-level limit with an advertised retry time holds everyone
	// until then — retrying earlier only burns the account budget further.
	assert.True(t, quarantine.IsQuarantined("app.example.com"))
	assert.True(t, quarantine.IsQuarantined("other.example.com"))
}

func TestBatchGuard_UnnamedRateLimitHoldsDeferredPartitionMembersToo(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, rateLimitedProblem(`too many new orders recently, retry after 2100-01-01 00:00:00 UTC: see docs`)
	}}
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine, nil)

	// Two DNS provider partitions: the handshake order narrows to the
	// trigger's partition, deferring the other member before the order.
	manager.selection.Zones = map[string]acmeconfig.ProviderName{
		"a.test": "cloudflare",
		"b.test": "route53",
	}
	require.NoError(t, manager.RegisterDomain("x.a.test", "service1"))
	require.NoError(t, manager.RegisterDomain("y.b.test", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "x.a.test")
	require.Error(t, err)

	// The account-level limit throttles every order from this account, so the
	// deferred member must wait out the advertised window too — its own
	// handshake would otherwise submit a doomed order immediately.
	assert.True(t, quarantine.IsQuarantined("x.a.test"))
	assert.True(t, quarantine.IsQuarantined("y.b.test"))
}

func TestBatchGuard_UnnamedRateLimitWithoutRetryTimeRestoresEverything(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, rateLimitedProblem(`too many new orders recently: see https://letsencrypt.org/docs/rate-limits/`)
	}}
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine, nil)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("other.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)

	// Nothing named, nothing advertised: same contract as any unattributable
	// failure — deploy-registered hosts stay off the quarantine ladder.
	assert.Equal(t, 0, quarantine.Len())
	pending := pendingDomainsOf(manager)
	assert.Contains(t, pending, "app.example.com")
	assert.Contains(t, pending, "other.example.com")
}

func TestBatchGuard_NoGuardInstalledPreservesBehavior(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, errors.New("acme: internal error")
	}}
	manager, _ := testGuardedManager(t, obtainer)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("other.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)

	pending := pendingDomainsOf(manager)
	assert.Contains(t, pending, "app.example.com")
	assert.Contains(t, pending, "other.example.com")
}
