package server

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIssuer(t testing.TB, obtainer certObtainer, config domainIssuerConfig) (*domainIssuer, *SANCertManager, *domainQuarantine) {
	t.Helper()

	manager := testSANCertManager(t)
	quarantine := newDomainQuarantine()

	config.Obtainer = obtainer
	issuer := newDomainIssuer(manager, quarantine, config)
	return issuer, manager, quarantine
}

func TestDomainIssuer_NextBatch_DefaultsToPerDomainOrders(t *testing.T) {
	issuer, manager, _ := testIssuer(t, successfulObtainer(t), domainIssuerConfig{})
	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com"})

	issuer.Request("a.example.com", "service1")
	issuer.Request("b.example.com", "service1")
	issuer.Request("a.example.com", "service1") // duplicate is dropped

	batch := issuer.nextBatch()
	require.Len(t, batch, 1)
	assert.Equal(t, "a.example.com", batch[0].domain)

	batch = issuer.nextBatch()
	require.Len(t, batch, 1)
	assert.Equal(t, "b.example.com", batch[0].domain)

	assert.Empty(t, issuer.nextBatch())
}

func TestDomainIssuer_NextBatch_BatchesSameServiceUpToSize(t *testing.T) {
	issuer, manager, _ := testIssuer(t, successfulObtainer(t), domainIssuerConfig{
		BatchSize: func(service string) int { return 2 },
	})
	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com", "c.example.com"})
	manager.SetDynamicDomains("service2", []string{"d.example.com"})

	issuer.Request("a.example.com", "service1")
	issuer.Request("d.example.com", "service2")
	issuer.Request("b.example.com", "service1")
	issuer.Request("c.example.com", "service1")

	batch := issuer.nextBatch()
	domains := []string{}
	for _, req := range batch {
		domains = append(domains, req.domain)
	}
	assert.ElementsMatch(t, []string{"a.example.com", "b.example.com"}, domains)

	batch = issuer.nextBatch()
	require.Len(t, batch, 1)
	assert.Equal(t, "d.example.com", batch[0].domain)

	batch = issuer.nextBatch()
	require.Len(t, batch, 1)
	assert.Equal(t, "c.example.com", batch[0].domain)
}

func TestDomainIssuer_NextBatch_SkipsQuarantinedAndDisallowed(t *testing.T) {
	issuer, manager, quarantine := testIssuer(t, successfulObtainer(t), domainIssuerConfig{})
	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com"})

	issuer.Request("a.example.com", "service1")
	issuer.Request("b.example.com", "service1")
	issuer.Request("evicted.example.com", "service1") // not in the dynamic set

	quarantine.RecordFailure("a.example.com", quarantineACME)

	batch := issuer.nextBatch()
	require.Len(t, batch, 1)
	assert.Equal(t, "b.example.com", batch[0].domain)
	assert.Empty(t, issuer.nextBatch())
}

func TestDomainIssuer_Issue_AdoptsCertificateAndClearsQuarantineHistory(t *testing.T) {
	obtainer := successfulObtainer(t)
	issuer, manager, quarantine := testIssuer(t, obtainer, domainIssuerConfig{})
	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	issuer.Request("tenant.example.com", "service1")
	issuer.issue(issuer.nextBatch())

	require.Len(t, obtainer.Calls(), 1)
	assert.Equal(t, []string{"tenant.example.com"}, obtainer.Calls()[0].Domains)
	assert.True(t, obtainer.Calls()[0].Bundle)

	assert.True(t, manager.HasValidCertificate("tenant.example.com"))
	assert.Equal(t, 0, quarantine.Len())
}

func TestDomainIssuer_Issue_QuarantinesFailingDomainAndRetriesSurvivorsOnce(t *testing.T) {
	failures := 0
	obtainer := &fakeObtainer{}
	obtainer.respond = func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		if len(request.Domains) == 2 {
			failures++
			// Mimic lego's per-domain error format
			return nil, fmt.Errorf("error: one or more domains had a problem:\nbad.example.com: acme: error presenting token")
		}
		return testCertResource(t, request.Domains, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)), nil
	}

	issuer, manager, quarantine := testIssuer(t, obtainer, domainIssuerConfig{
		BatchSize: func(service string) int { return 2 },
	})
	manager.SetDynamicDomains("service1", []string{"good.example.com", "bad.example.com"})

	issuer.Request("good.example.com", "service1")
	issuer.Request("bad.example.com", "service1")

	issuer.issue(issuer.nextBatch())

	// bad.example.com is quarantined; good.example.com was re-enqueued once
	assert.True(t, quarantine.IsQuarantined("bad.example.com"))
	assert.False(t, quarantine.IsQuarantined("good.example.com"))

	batch := issuer.nextBatch()
	require.Len(t, batch, 1)
	assert.Equal(t, "good.example.com", batch[0].domain)
	assert.True(t, batch[0].retried)

	issuer.issue(batch)
	assert.True(t, manager.HasValidCertificate("good.example.com"))
	assert.False(t, manager.HasValidCertificate("bad.example.com"))
	require.Len(t, obtainer.Calls(), 2)
}

func TestDomainIssuer_Issue_UnidentifiableFailureQuarantinesWholeBatch(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, errors.New("acme: connection refused")
	}}

	issuer, manager, quarantine := testIssuer(t, obtainer, domainIssuerConfig{
		BatchSize: func(service string) int { return 2 },
	})
	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com"})

	issuer.Request("a.example.com", "service1")
	issuer.Request("b.example.com", "service1")
	issuer.issue(issuer.nextBatch())

	assert.True(t, quarantine.IsQuarantined("a.example.com"))
	assert.True(t, quarantine.IsQuarantined("b.example.com"))
	assert.Empty(t, issuer.nextBatch())
	require.Len(t, obtainer.Calls(), 1)
}

func TestDomainIssuer_Issue_RetriedSurvivorsAreNotReenqueuedAgain(t *testing.T) {
	obtainer := &fakeObtainer{respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, fmt.Errorf("error: one or more domains had a problem:\n%s: acme: failed", request.Domains[0])
	}}

	issuer, manager, quarantine := testIssuer(t, obtainer, domainIssuerConfig{
		BatchSize: func(service string) int { return 3 },
	})
	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com", "c.example.com"})

	issuer.Request("a.example.com", "service1")
	issuer.Request("b.example.com", "service1")
	issuer.Request("c.example.com", "service1")

	issuer.issue(issuer.nextBatch()) // fails a; b, c re-enqueued
	issuer.issue(issuer.nextBatch()) // fails b; c was already retried -> quarantined, not re-enqueued

	assert.True(t, quarantine.IsQuarantined("a.example.com"))
	assert.True(t, quarantine.IsQuarantined("b.example.com"))
	assert.True(t, quarantine.IsQuarantined("c.example.com"))
	assert.Empty(t, issuer.nextBatch())
	require.Len(t, obtainer.Calls(), 2)
}

func TestDomainIssuer_Issue_PreflightFailureQuarantinesWithoutBurningAnOrder(t *testing.T) {
	obtainer := successfulObtainer(t)
	issuer, manager, quarantine := testIssuer(t, obtainer, domainIssuerConfig{
		Preflight: func(domain string) error { return errors.New("connection refused") },
	})
	manager.SetDynamicDomains("service1", []string{"unreachable.example.com"})

	issuer.Request("unreachable.example.com", "service1")
	issuer.issue(issuer.nextBatch())

	assert.True(t, quarantine.IsQuarantined("unreachable.example.com"))
	assert.Empty(t, obtainer.Calls())
}

func TestDomainIssuer_Issue_PreflightSkippedWhenCertificateExists(t *testing.T) {
	preflights := 0
	obtainer := successfulObtainer(t)
	issuer, manager, _ := testIssuer(t, obtainer, domainIssuerConfig{
		Preflight: func(domain string) error { preflights++; return errors.New("unreachable") },
	})
	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	// An expired certificate still counts as "issued before": skip preflight
	manager.certificates["san:old"] = &ManagedCert{
		Identifier: "san:old",
		Domains:    []string{"tenant.example.com"},
		NotAfter:   time.Now().Add(-time.Hour),
	}
	manager.domainToCert["tenant.example.com"] = "san:old"

	issuer.Request("tenant.example.com", "service1")
	issuer.issue(issuer.nextBatch())

	assert.Equal(t, 0, preflights)
	require.Len(t, obtainer.Calls(), 1)
}

func TestDomainIssuer_WorkerIssuesAsynchronously(t *testing.T) {
	obtainer := successfulObtainer(t)
	issuer, manager, _ := testIssuer(t, obtainer, domainIssuerConfig{})
	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	issuer.Start()
	t.Cleanup(issuer.Stop)

	issuer.Request("tenant.example.com", "service1")

	require.Eventually(t, func() bool {
		return manager.HasValidCertificate("tenant.example.com")
	}, 5*time.Second, 10*time.Millisecond)
}
