package server

import (
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

func TestCertRenewer_DropsCertificateWhenAllDomainsEvicted(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)

	adoptTestCert(t, manager, []string{"gone.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))
	// Not registered, not dynamic: fully evicted

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: obtainer})
	renewer.reconcile()

	assert.Empty(t, obtainer.Calls())
	assert.Empty(t, manager.ManagedCertificates())
	assert.False(t, manager.HasCertificate("gone.example.com"))
}

func TestCertRenewer_ExcludesQuarantinedDomains(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	manager.SetDynamicDomains("service1", []string{"ok.example.com", "flaky.example.com"})
	adoptTestCert(t, manager, []string{"flaky.example.com", "ok.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

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
		Obtainer:    obtainer,
		BatchSize:   func(service string) int { return 3 },
		TakePending: issuer.takePending,
	})
	renewer.reconcile()

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.ElementsMatch(t, []string{"a.example.com", "b.example.com", "c.example.com"}, calls[0].Domains)
	assert.Equal(t, 0, issuer.QueueLen())
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
