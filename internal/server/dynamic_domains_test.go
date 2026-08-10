package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeResolver struct {
	services map[string]*Service
}

func (f *fakeResolver) serviceForName(name string) *Service {
	return f.services[name]
}

func testDynamicDomainManager(t testing.TB, config DynamicDomainConfig) (*DynamicDomainManager, *SANCertManager) {
	t.Helper()

	if config.StatePath == "" {
		config.StatePath = filepath.Join(t.TempDir(), "dynamic-domains.state")
	}

	manager := testSANCertManager(t)
	resolver := &fakeResolver{services: map[string]*Service{
		"service1": {name: "service1"},
		"service2": {name: "service2"},
	}}
	dm := NewDynamicDomainManager(config, manager, resolver)
	dm.issuer.config.Obtainer = successfulObtainer(t)
	dm.issuer.config.Preflight = nil

	// Stop the pollers before the state file's TempDir is removed. Without this
	// a source outlives the test and races the cleanup, which surfaces as
	// "TempDir RemoveAll cleanup: directory not empty". Stop is idempotent, so
	// tests calling it themselves are unaffected.
	t.Cleanup(dm.Stop)

	return dm, manager
}

func testDomainsBackend(t testing.TB, domains ...string) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	polls := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		payload := `{"domains": [`
		for i, d := range domains {
			if i > 0 {
				payload += ","
			}
			payload += fmt.Sprintf("%q", d)
		}
		payload += `]}`
		fmt.Fprint(w, payload)
	}))
	t.Cleanup(server.Close)

	return server, polls
}

func TestDynamicDomainManager_DeployedServicePollsAndIssues(t *testing.T) {
	backend, _ := testDomainsBackend(t, "tenant.example.com")
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})

	dm.Start()
	t.Cleanup(dm.Stop)

	dm.ServiceDeployed("service1", ServiceOptions{
		TLSEnabled:       true,
		TLSDomainsSource: backend.URL,
	})

	require.Eventually(t, func() bool {
		return manager.HasValidCertificate("tenant.example.com")
	}, 5*time.Second, 10*time.Millisecond)

	assert.ElementsMatch(t, []string{"tenant.example.com"}, manager.DynamicDomains("service1"))
}

func TestDynamicDomainManager_StateSurvivesRestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dynamic-domains.state")
	backend, _ := testDomainsBackend(t, "tenant.example.com")

	dm, _ := testDynamicDomainManager(t, DynamicDomainConfig{StatePath: statePath})
	dm.ServiceDeployed("service1", ServiceOptions{
		TLSEnabled:       true,
		TLSDomainsSource: backend.URL,
	})
	dm.applyDomains("service1", []string{"tenant.example.com"})
	dm.quarantine.RecordFailure("bad.example.com", quarantineACME)
	dm.Stop()

	// A fresh manager restores state and applies persisted domains on deploy,
	// before any poll happens.
	dm2, manager2 := testDynamicDomainManager(t, DynamicDomainConfig{StatePath: statePath})
	assert.True(t, dm2.quarantine.IsQuarantined("bad.example.com"))

	dm2.ServiceDeployed("service1", ServiceOptions{
		TLSEnabled:       true,
		TLSDomainsSource: backend.URL,
	})
	assert.ElementsMatch(t, []string{"tenant.example.com"}, manager2.DynamicDomains("service1"))
}

func TestDynamicDomainManager_ServiceRemovedEvictsDomains(t *testing.T) {
	backend, _ := testDomainsBackend(t, "tenant.example.com")
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{TLSEnabled: true, TLSDomainsSource: backend.URL})
	dm.applyDomains("service1", []string{"tenant.example.com"})
	require.NotEmpty(t, manager.DynamicDomains("service1"))

	dm.ServiceRemoved("service1")
	assert.Empty(t, manager.DynamicDomains("service1"))
	assert.False(t, manager.DomainAllowed("tenant.example.com"))
}

func TestDynamicDomainManager_RedeployWithoutSourceEvictsDomains(t *testing.T) {
	backend, _ := testDomainsBackend(t, "tenant.example.com")
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{TLSEnabled: true, TLSDomainsSource: backend.URL})
	dm.applyDomains("service1", []string{"tenant.example.com"})

	dm.ServiceDeployed("service1", ServiceOptions{TLSEnabled: true, Hosts: []string{"app.example.com"}})
	assert.Empty(t, manager.DynamicDomains("service1"))
}

func TestDynamicDomainManager_RefreshEndpoint(t *testing.T) {
	backend, polls := testDomainsBackend(t, "tenant.example.com")

	dm, _ := testDynamicDomainManager(t, DynamicDomainConfig{RefreshToken: "refresh-secret"})
	dm.Start()
	t.Cleanup(dm.Stop)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	handler := dm.WrapHandler(next)

	post := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://anything.example.com/.kamal-proxy/domains/refresh", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	// No sources configured yet -> 404
	assert.Equal(t, http.StatusNotFound, post("refresh-secret").Code)

	dm.ServiceDeployed("service1", ServiceOptions{TLSEnabled: true, TLSDomainsSource: backend.URL})
	initialPolls := polls.Load()

	// Bad or missing token -> 401
	assert.Equal(t, http.StatusUnauthorized, post("wrong").Code)
	assert.Equal(t, http.StatusUnauthorized, post("").Code)

	// Valid -> 202 and triggers a poll
	assert.Equal(t, http.StatusAccepted, post("refresh-secret").Code)
	require.Eventually(t, func() bool { return polls.Load() > initialPolls }, 5*time.Second, 10*time.Millisecond)

	// Within the min interval -> 429
	assert.Equal(t, http.StatusTooManyRequests, post("refresh-secret").Code)

	// Unrelated paths fall through
	req := httptest.NewRequest(http.MethodGet, "http://anything.example.com/some/path", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTeapot, w.Code)
}

func TestDynamicDomainManager_RefreshEndpointDisabledWithoutToken(t *testing.T) {
	backend, _ := testDomainsBackend(t, "tenant.example.com")

	dm, _ := testDynamicDomainManager(t, DynamicDomainConfig{})
	dm.ServiceDeployed("service1", ServiceOptions{TLSEnabled: true, TLSDomainsSource: backend.URL})

	handler := dm.WrapHandler(http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodPost, "http://x/.kamal-proxy/domains/refresh", nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicDomainManager_PreflightEndpoint(t *testing.T) {
	dm, _ := testDynamicDomainManager(t, DynamicDomainConfig{})
	handler := dm.WrapHandler(http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodGet, "http://x/.kamal-proxy/preflight/"+dm.preflightNonce, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, dm.preflightNonce, w.Body.String())

	req = httptest.NewRequest(http.MethodGet, "http://x/.kamal-proxy/preflight/wrong-nonce", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicDomainManager_Status(t *testing.T) {
	backend, _ := testDomainsBackend(t, "tenant.example.com", "pending.example.com")
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{TLSEnabled: true, TLSDomainsSource: backend.URL})
	dm.applyDomains("service1", []string{"tenant.example.com", "pending.example.com"})
	dm.quarantine.RecordFailure("pending.example.com", quarantineACME)

	adoptTestCert(t, manager, []string{"tenant.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	status := dm.Status()

	require.Contains(t, status.Services, "service1")
	service := status.Services["service1"]
	assert.Equal(t, backend.URL, service.Source)
	assert.ElementsMatch(t, []DomainStatus{
		{Domain: "tenant.example.com", Certified: true},
		{Domain: "pending.example.com", Certified: false},
	}, service.Domains)

	require.Contains(t, status.Quarantine, "pending.example.com")
	assert.Equal(t, 1, status.Quarantine["pending.example.com"].Failures)
	assert.Equal(t, 1, status.Certificates)
}

// deployWithDomains deploys a service whose source serves the given domains
// and waits for the initial poll to land, so later applyDomains calls diff
// against a known baseline.
func deployWithDomains(t testing.TB, dm *DynamicDomainManager, manager *SANCertManager, service string, domains []string) {
	t.Helper()

	backend, _ := testDomainsBackend(t, domains...)
	dm.ServiceDeployed(service, ServiceOptions{TLSEnabled: true, TLSDomainsSource: backend.URL})
	require.Eventually(t, func() bool {
		return len(manager.DynamicDomains(service)) == len(domains)
	}, 5*time.Second, 10*time.Millisecond)
}

func testTenantDomains(n int) []string {
	domains := make([]string, 0, n)
	for i := 0; i < n; i++ {
		domains = append(domains, fmt.Sprintf("tenant-%d.example.com", i))
	}
	return domains
}

func TestDynamicDomainManager_ShrinkGuardHoldsMassRemovals(t *testing.T) {
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})
	full := testTenantDomains(10)
	deployWithDomains(t, dm, manager, "service1", full)

	// One poll drops 6 of 10 domains and adds one: the removals are held, the
	// addition applies immediately.
	shrunk := append(append([]string{}, full[:4]...), "new.example.com")
	dm.applyDomains("service1", shrunk)

	assert.Len(t, manager.DynamicDomains("service1"), 11)
	assert.True(t, manager.DomainAllowed("tenant-9.example.com"))
	assert.True(t, manager.DomainAllowed("new.example.com"))

	status := dm.Status()
	assert.Len(t, status.Services["service1"].HeldRemovals, 6)
}

func TestDynamicDomainManager_ShrinkGuardHoldsEmptyPoll(t *testing.T) {
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})
	full := testTenantDomains(10)
	deployWithDomains(t, dm, manager, "service1", full)

	dm.applyDomains("service1", []string{})

	assert.Len(t, manager.DynamicDomains("service1"), 10)
	assert.Len(t, dm.Status().Services["service1"].HeldRemovals, 10)
}

func TestDynamicDomainManager_ShrinkGuardAppliesSmallRemovals(t *testing.T) {
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})
	full := testTenantDomains(10)
	deployWithDomains(t, dm, manager, "service1", full)

	// Removing 1 of 10 is below the threshold: applied immediately.
	dm.applyDomains("service1", full[:9])

	assert.Len(t, manager.DynamicDomains("service1"), 9)
	assert.False(t, manager.DomainAllowed("tenant-9.example.com"))
	assert.Empty(t, dm.Status().Services["service1"].HeldRemovals)
}

func TestDynamicDomainManager_ShrinkGuardConfirmsAfterConsecutivePolls(t *testing.T) {
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})
	full := testTenantDomains(10)
	deployWithDomains(t, dm, manager, "service1", full)

	shrunk := full[:4]

	// Two consecutive over-threshold polls are held...
	dm.applyDomains("service1", shrunk)
	dm.applyDomains("service1", shrunk)
	assert.Len(t, manager.DynamicDomains("service1"), 10)

	// ...the third confirms the shrink and applies it.
	dm.applyDomains("service1", shrunk)
	assert.ElementsMatch(t, shrunk, manager.DynamicDomains("service1"))
	assert.Empty(t, dm.Status().Services["service1"].HeldRemovals)
}

func TestDynamicDomainManager_ShrinkGuardClearsETagWhileHolding(t *testing.T) {
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})
	full := testTenantDomains(10)
	deployWithDomains(t, dm, manager, "service1", full)

	// An ETag-answering source would 304 every poll after the held response,
	// and the confirmation count could never advance. Holding must drop the
	// ETag so the body keeps being refetched until the shrink resolves.
	dm.mu.Lock()
	dm.sources["service1"].SeedETag(`"v2"`)
	dm.mu.Unlock()

	dm.applyDomains("service1", full[:4])

	dm.mu.Lock()
	etag := dm.sources["service1"].ETag()
	stored := dm.states["service1"].ETag
	dm.mu.Unlock()
	assert.Empty(t, etag)
	assert.Empty(t, stored)
}

func TestDynamicDomainManager_ShrinkGuardResetsOnRedeploy(t *testing.T) {
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})
	full := testTenantDomains(10)
	deployWithDomains(t, dm, manager, "service1", full)

	dm.applyDomains("service1", full[:4])
	dm.mu.Lock()
	_, held := dm.holds["service1"]
	dm.mu.Unlock()
	require.True(t, held)

	// A redeploy replaces the source; confirmations counted against the old
	// source must not carry over to the new one.
	backend, _ := testDomainsBackend(t, full...)
	dm.ServiceDeployed("service1", ServiceOptions{TLSEnabled: true, TLSDomainsSource: backend.URL})

	dm.mu.Lock()
	_, held = dm.holds["service1"]
	dm.mu.Unlock()
	assert.False(t, held)
}

func TestDynamicDomainManager_ShrinkGuardCancelsOnRecovery(t *testing.T) {
	dm, manager := testDynamicDomainManager(t, DynamicDomainConfig{})
	full := testTenantDomains(10)
	deployWithDomains(t, dm, manager, "service1", full)

	shrunk := full[:4]

	// A held shrink followed by a recovering poll clears the hold — and the
	// confirmation count starts over for the next shrink.
	dm.applyDomains("service1", shrunk)
	dm.applyDomains("service1", full)
	assert.Empty(t, dm.Status().Services["service1"].HeldRemovals)

	dm.applyDomains("service1", shrunk)
	dm.applyDomains("service1", shrunk)
	assert.Len(t, manager.DynamicDomains("service1"), 10)

	dm.applyDomains("service1", shrunk)
	assert.ElementsMatch(t, shrunk, manager.DynamicDomains("service1"))
}

func TestDynamicDomainManager_PreflightProbe(t *testing.T) {
	dm, _ := testDynamicDomainManager(t, DynamicDomainConfig{})

	// Serve the proxy's own handler, as a correctly-routed domain would
	server := httptest.NewServer(dm.WrapHandler(http.NotFoundHandler()))
	t.Cleanup(server.Close)

	// Route all probe traffic to the test server, regardless of domain
	dm.probeClient = &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, server.Listener.Addr().String())
			},
		},
	}

	require.NoError(t, dm.preflightProbe("tenant.example.com"))

	// A domain that routes elsewhere fails the probe
	other := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(other.Close)
	dm.probeClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, other.Listener.Addr().String())
		},
	}

	require.Error(t, dm.preflightProbe("tenant.example.com"))
}

func TestDynamicDomainManager_PreflightProbeRefusesRedirects(t *testing.T) {
	dm, _ := testDynamicDomainManager(t, DynamicDomainConfig{})

	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.Write([]byte(dm.preflightNonce))
	}))
	t.Cleanup(target.Close)

	// The probed (tenant-controlled) server answers with a redirect — the
	// probe must fail without following it (SSRF).
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	dm.probeClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, redirector.Listener.Addr().String())
		},
	}

	require.Error(t, dm.preflightProbe("evil.example.com"))
	assert.False(t, redirected)
}

func TestDynamicDomainManager_LoadStateSkipsNilEntries(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dynamic-domains.state")
	require.NoError(t, os.WriteFile(statePath,
		[]byte(`{"services":{"broken":null,"ok":{"domains":["tenant.example.com"]}}}`), 0600))

	dm, _ := testDynamicDomainManager(t, DynamicDomainConfig{StatePath: statePath})

	// Must not panic, and the valid entry must survive
	status := dm.Status()
	assert.NotContains(t, status.Services, "broken")
	assert.Contains(t, status.Services, "ok")
}
