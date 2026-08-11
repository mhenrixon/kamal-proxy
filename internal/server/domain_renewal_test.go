package server

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeARIObtainer adds ACME Renewal Information support to fakeObtainer.
type fakeARIObtainer struct {
	*fakeObtainer
	window acme.Window
}

func (f *fakeARIObtainer) GetRenewalInfo(request certificate.RenewalInfoRequest) (*certificate.RenewalInfoResponse, error) {
	response := &certificate.RenewalInfoResponse{}
	response.SuggestedWindow = f.window
	return response, nil
}

// adoptTestCert installs a certificate with a controlled validity window.
func adoptTestCert(t testing.TB, manager *SANCertManager, domains []string, notBefore, notAfter time.Time) *ManagedCert {
	t.Helper()

	resource := testCertResource(t, domains, notBefore, notAfter)
	managed, err := manager.adoptCertificate(resource, domains)
	require.NoError(t, err)
	return managed
}

func TestCertRenewer_RenewsInsideFallbackWindow(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})
	// 90-day lifetime, 20 days left: past the NotAfter - lifetime/3 threshold
	// even with maximum jitter (6h)
	adoptTestCert(t, manager, []string{"tenant.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"tenant.example.com"}, calls[0].Domains)
	assert.NotEmpty(t, calls[0].ReplacesCertID, "renewal must pass ARI replaces")

	// Identical set -> same identifier, refreshed expiry
	certs := manager.ManagedCertificates()
	require.Len(t, certs, 1)
	assert.Greater(t, time.Until(certs[0].NotAfter), 80*24*time.Hour)
}

func TestCertRenewer_LeavesFreshCertificatesAlone(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})
	adoptTestCert(t, manager, []string{"tenant.example.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(89*24*time.Hour))

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
}

func TestCertRenewer_HonorsARIWindow(t *testing.T) {
	manager := testSANCertManager(t)
	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	// Fresh certificate, but ARI suggests renewing now
	adoptTestCert(t, manager, []string{"tenant.example.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(89*24*time.Hour))

	obtainer := &fakeARIObtainer{
		fakeObtainer: successfulObtainer(t),
		window:       acme.Window{Start: time.Now().Add(-2 * time.Hour), End: time.Now().Add(-time.Hour)},
	}
	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()
	require.Len(t, obtainer.Calls(), 1)

	// And the reverse: overdue by the fallback rule, but ARI says wait
	manager2 := testSANCertManager(t)
	manager2.SetDynamicDomains("service1", []string{"tenant.example.com"})
	adoptTestCert(t, manager2, []string{"tenant.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	waiting := &fakeARIObtainer{
		fakeObtainer: successfulObtainer(t),
		window:       acme.Window{Start: time.Now().Add(10 * 24 * time.Hour), End: time.Now().Add(11 * 24 * time.Hour)},
	}
	renewer2 := newCertRenewer(manager2, newDomainQuarantine(), certRenewerConfig{Obtainer: waiting})
	renewer2.reconcile()
	assert.Empty(t, waiting.Calls())
}

func TestCertRenewer_DropsEvictedDomainsAtRenewal(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	old := adoptTestCert(t, manager, []string{"gone.example.com", "kept.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	// Only kept.example.com is still in the dynamic set
	manager.SetDynamicDomains("service1", []string{"kept.example.com"})

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"kept.example.com"}, calls[0].Domains)

	// The old certificate is gone; the evicted domain no longer maps anywhere
	assert.False(t, manager.HasCertificate("gone.example.com"))
	assert.True(t, manager.HasValidCertificate("kept.example.com"))

	certs := manager.ManagedCertificates()
	require.Len(t, certs, 1)
	assert.NotEqual(t, old.Identifier, certs[0].Identifier)
}

func TestCertRenewer_KeepsFullyEvictedCertificateUntilExpiry(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	adoptTestCert(t, manager, []string{"gone.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))
	// Not registered, not dynamic: fully evicted. Eviction can be a lying
	// domain source — the certificate must survive until its own expiry, not
	// be renewed, and not be deleted.

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	require.Len(t, manager.ManagedCertificates(), 1)
	assert.True(t, manager.HasValidCertificate("gone.example.com"))
}

func TestCertRenewer_RemovesFullyEvictedCertificateAfterExpiry(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	adoptTestCert(t, manager, []string{"gone.example.com"},
		time.Now().Add(-91*24*time.Hour), time.Now().Add(-time.Hour))

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	assert.Empty(t, manager.ManagedCertificates())
	assert.False(t, manager.HasCertificate("gone.example.com"))
}

func TestCertRenewer_EvictedCertificateSurvivesSourceRecovery(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	adoptTestCert(t, manager, []string{"tenant.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(89*24*time.Hour))

	// A bad poll evicts everything; the reconcile in between must not delete
	// the certificate, so recovery costs zero new orders.
	manager.SetDynamicDomains("service1", nil)
	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	assert.True(t, manager.HasValidCertificate("tenant.example.com"))
}

func TestCertRenewer_RemovesSupersededCertificateImmediately(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com", "c.example.com"})

	old := adoptTestCert(t, manager, []string{"a.example.com", "b.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))
	// Every domain of the old certificate now maps to the newer, wider one:
	// nothing serves through the old cert, so it goes immediately, unexpired.
	current := adoptTestCert(t, manager, []string{"a.example.com", "b.example.com", "c.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(89*24*time.Hour))

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	certs := manager.ManagedCertificates()
	require.Len(t, certs, 1)
	assert.Equal(t, current.Identifier, certs[0].Identifier)
	assert.NotEqual(t, old.Identifier, certs[0].Identifier)
}

func TestCertRenewer_DefersPartiallyQuarantinedBatchWhenTimeAllows(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"ok.example.com", "flaky.example.com"})
	// In the renewal window but with 20 days of validity left: renewing
	// without the quarantined member would unmap its still-valid certificate
	// and change the identifier set. Wait for the quarantine instead.
	adoptTestCert(t, manager, []string{"flaky.example.com", "ok.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	quarantine.RecordFailure("flaky.example.com", quarantineACME)

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	require.Len(t, manager.ManagedCertificates(), 1)
}

func TestCertRenewer_CompactsQuarantinedDomainsNearExpiry(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"ok.example.com", "flaky.example.com"})
	// Only 3 days left: waiting for the quarantine would risk expiring the
	// healthy member — renew without the quarantined one
	adoptTestCert(t, manager, []string{"flaky.example.com", "ok.example.com"},
		time.Now().Add(-87*24*time.Hour), time.Now().Add(3*24*time.Hour))

	quarantine.RecordFailure("flaky.example.com", quarantineACME)

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"ok.example.com"}, calls[0].Domains)
}

func TestCertRenewer_TopsUpBatchOnlyAtRenewal(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com", "c.example.com"})
	adoptTestCert(t, manager, []string{"a.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	issuer := newDomainIssuer(manager, quarantine, domainIssuerConfig{Obtainer: obtainer})
	issuer.Request("b.example.com", "service1")
	issuer.Request("c.example.com", "service1")

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{
		Obtainer:       obtainer,
		BatchSize:      func(service string) int { return 3 },
		TakePending:    issuer.takePending,
		ReleasePending: issuer.releasePending,
	})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.ElementsMatch(t, []string{"a.example.com", "b.example.com", "c.example.com"}, calls[0].Domains)
	assert.Equal(t, 0, issuer.QueueLen())

	// The taken domains were released after the order completed
	issuer.Request("d.example.com", "service1")
	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"})
	assert.NotEmpty(t, issuer.nextBatch())
}

func TestCertRenewer_TopUpPreflightsNewDomains(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"a.example.com", "unreachable.example.com"})
	adoptTestCert(t, manager, []string{"a.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	issuer := newDomainIssuer(manager, quarantine, domainIssuerConfig{Obtainer: obtainer})
	issuer.Request("unreachable.example.com", "service1")

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{
		Obtainer:       obtainer,
		BatchSize:      func(service string) int { return 3 },
		TakePending:    issuer.takePending,
		ReleasePending: issuer.releasePending,
		Preflight: func(domain string) error {
			if domain == "unreachable.example.com" {
				return errors.New("does not route here")
			}
			return nil
		},
	})
	renewer.reconcile()

	// The never-issued domain failed its probe: quarantined, not ordered
	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"a.example.com"}, calls[0].Domains)
	assert.True(t, quarantine.IsQuarantined("unreachable.example.com"))
}

func TestCertRenewer_ProbesDynamicMembersBeforeRenewal(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"ok.example.com", "dead.example.com"})
	// Within the compaction window: the unreachable member is dropped from
	// the order instead of sinking it at the ACME server.
	adoptTestCert(t, manager, []string{"dead.example.com", "ok.example.com"},
		time.Now().Add(-87*24*time.Hour), time.Now().Add(3*24*time.Hour))

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{
		Obtainer: obtainer,
		Preflight: func(domain string) error {
			if domain == "dead.example.com" {
				return errors.New("does not route here")
			}
			return nil
		},
	})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"ok.example.com"}, calls[0].Domains)
	assert.True(t, quarantine.IsQuarantined("dead.example.com"))
}

func TestCertRenewer_DefersRenewalWhenMemberFailsProbeFarFromExpiry(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"ok.example.com", "dead.example.com"})
	// 20 days left: wait for the unreachable member rather than unmapping it
	// from a still-valid certificate.
	adoptTestCert(t, manager, []string{"dead.example.com", "ok.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{
		Obtainer: obtainer,
		Preflight: func(domain string) error {
			if domain == "dead.example.com" {
				return errors.New("does not route here")
			}
			return nil
		},
	})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	assert.True(t, quarantine.IsQuarantined("dead.example.com"))
	require.Len(t, manager.ManagedCertificates(), 1)
}

func TestCertRenewer_DefersRenewalWhenAllMembersFailProbe(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"dead.example.com"})
	adoptTestCert(t, manager, []string{"dead.example.com"},
		time.Now().Add(-87*24*time.Hour), time.Now().Add(3*24*time.Hour))

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{
		Obtainer:  obtainer,
		Preflight: func(domain string) error { return errors.New("does not route here") },
	})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	require.Len(t, manager.ManagedCertificates(), 1)
}

func TestCertRenewer_SkipsProbeForRegisteredMembers(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	// Deploy-registered hosts are not probed: a DNS-01-only deployment may
	// be unreachable over HTTP by design, and must still renew.
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	adoptTestCert(t, manager, []string{"app.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{
		Obtainer:  obtainer,
		Preflight: func(domain string) error { return errors.New("unreachable over HTTP") },
	})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"app.example.com"}, calls[0].Domains)
	assert.False(t, quarantine.IsQuarantined("app.example.com"))
}

func TestCertRenewer_QuarantinesWholeBatchOnUnattributableFailure(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, errors.New("acme: internal error")
	}}
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com"})
	adoptTestCert(t, manager, []string{"a.example.com", "b.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{
		Obtainer:  obtainer,
		Preflight: func(domain string) error { return nil },
	})
	renewer.reconcile()

	// The failure names no domain and every member probes clean: hold the
	// whole batch on the quarantine ladder so retries back off instead of
	// looping hourly until the certificate expires.
	assert.True(t, quarantine.IsQuarantined("a.example.com"))
	assert.True(t, quarantine.IsQuarantined("b.example.com"))
	require.Len(t, manager.ManagedCertificates(), 1)
}

func TestCertRenewer_SkipsCertificatesNoLongerReferenced(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	// tenant.example.com moved to a newer certificate, but the evicted
	// gone.example.com still maps to (and is served by) the old one: the old
	// cert must not be renewed, and must survive until its own expiry.
	old := adoptTestCert(t, manager, []string{"gone.example.com", "tenant.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))
	current := adoptTestCert(t, manager, []string{"tenant.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(89*24*time.Hour))

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())

	certs := manager.ManagedCertificates()
	require.Len(t, certs, 2)
	assert.Equal(t, current.Identifier, manager.certIDForDomain("tenant.example.com"))
	assert.Equal(t, old.Identifier, manager.certIDForDomain("gone.example.com"))
}

func TestCertRenewer_SkipsRenewalWhenAllDomainsQuarantined(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"flaky.example.com"})
	adoptTestCert(t, manager, []string{"flaky.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	quarantine.RecordFailure("flaky.example.com", quarantineACME)

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	// The domain is still allowed — only quarantined. The certificate must
	// keep serving; renewal just waits for the quarantine to lift.
	assert.Empty(t, obtainer.Calls())
	require.Len(t, manager.ManagedCertificates(), 1)
	assert.True(t, manager.HasCertificate("flaky.example.com"))
}

func TestCertRenewer_QuarantinesCulpritsOnFailure(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, fmt.Errorf("error: one or more domains had a problem:\nbad.example.com: acme: dns problem")
	}}
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"bad.example.com", "ok.example.com"})
	adoptTestCert(t, manager, []string{"bad.example.com", "ok.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	renewer := newCertRenewer(manager, quarantine, certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.True(t, quarantine.IsQuarantined("bad.example.com"))
	assert.False(t, quarantine.IsQuarantined("ok.example.com"))

	// The certificate is untouched and keeps serving until a renewal succeeds
	certs := manager.ManagedCertificates()
	require.Len(t, certs, 1)
}

func TestCertRenewer_ReissuesImmediatelyWhenDirectoryChanges(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	// A fresh certificate, nowhere near its renewal window — but the service
	// has since flipped to a different ACME directory.
	adoptTestCert(t, manager, []string{"tenant.example.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(89*24*time.Hour))
	manager.SetServiceDirectory("service1", LetsEncryptProduction)

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	require.Len(t, obtainer.Calls(), 1, "a directory switch must re-issue on the next reconcile")

	// The replacement records the new directory, so the next reconcile is quiet.
	certs := manager.ManagedCertificates()
	require.Len(t, certs, 1)
	assert.Equal(t, LetsEncryptProduction, certs[0].Directory)

	renewer.reconcile()
	assert.Len(t, obtainer.Calls(), 1)
}

func TestCertRenewer_DirectoryChanged(t *testing.T) {
	manager := testSANCertManager(t)
	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: successfulObtainer(t)})

	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	legacy := &ManagedCert{Domains: []string{"tenant.example.com"}}
	assert.False(t, renewer.directoryChanged(legacy),
		"an empty recorded directory reads as the run-level one")

	manager.SetServiceDirectory("service1", LetsEncryptProduction)
	assert.True(t, renewer.directoryChanged(legacy))

	orphan := &ManagedCert{Domains: []string{"gone.example.net"}, Directory: LetsEncryptProduction}
	assert.False(t, renewer.directoryChanged(orphan),
		"a certificate with no resolvable owner keeps its recorded directory")
}
