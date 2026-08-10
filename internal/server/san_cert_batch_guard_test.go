package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	manager.SetIssuanceGuard(nil, quarantine)

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
	}, quarantine)

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

func TestBatchGuard_TriggerDomainIsNeverDropped(t *testing.T) {
	obtainer := successfulObtainer(t)
	manager, quarantine := testGuardedManager(t, obtainer)
	// The probe fails everything, and the trigger is even quarantined — its
	// handshake still gets its shot.
	manager.SetIssuanceGuard(func(domain string) error { return errors.New("unreachable") }, quarantine)
	quarantine.RecordFailure("app.example.com", quarantineACME)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.NoError(t, err)

	calls := obtainer.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"app.example.com"}, calls[0].Domains)
}

func TestBatchGuard_QuarantinesCulpritsAndRestoresSurvivorsOnFailure(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, fmt.Errorf("error: one or more domains had a problem:\nbad.example.com: acme: error presenting token")
	}}
	manager, quarantine := testGuardedManager(t, obtainer)
	manager.SetIssuanceGuard(nil, quarantine)

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
	manager.SetIssuanceGuard(func(domain string) error { return nil }, quarantine)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("other.example.com", "service1"))

	_, err := manager.provisionCertificate(context.Background(), "app.example.com")
	require.Error(t, err)

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
