package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The published v1.0.0.0 image would provision a Let's Encrypt certificate for
// any server name presented at the handshake: the certificate registry issued
// on lookup, with neither an allowlist nor a ceiling on distinct domains. These
// tests pin the replacement contract -- one cert system, one allowlist, and a
// refusal for everything else.

// A host that routes to no service at all must not reach a cert system.
func TestRouter_GetCertificate_RefusesServerNameWithNoService(t *testing.T) {
	router := testRouter(t)
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.dnsObtainer = obtainer

	router.SetSANCertManager(manager)

	_, target := testBackend(t, "first", http.StatusOK)
	certPath, keyPath := prepareTestCertificateFiles(t)

	serviceOptions := defaultServiceOptions
	serviceOptions.TLSEnabled = true
	serviceOptions.Hosts = []string{"app.example.com"}
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath

	require.NoError(t, router.DeployService("hostscoped", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	_, err := router.GetCertificate(&tls.ClientHelloInfo{ServerName: "attacker.example.net"})

	assert.ErrorIs(t, err, ErrorUnknownServerName)
	assert.Empty(t, obtainer.Calls(), "an unrouted server name must cost no ACME order")
}

// A catch-all service routes every server name, so the service lookup cannot be
// the gate -- the manager's allowlist is. Pointing a DNS record at the proxy and
// sending that name as SNI must provision nothing.
func TestRouter_GetCertificate_CatchAllServiceRefusesUnallowedServerName(t *testing.T) {
	router := testRouter(t)
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer
	manager.dnsObtainer = obtainer

	router.SetSANCertManager(manager)

	_, target := testBackend(t, "first", http.StatusOK)

	serviceOptions := defaultServiceOptions
	serviceOptions.TLSEnabled = true
	serviceOptions.ACMECachePath = t.TempDir()
	serviceOptions.TLSDomainsSource = "/domains"

	require.NoError(t, router.DeployService("catchall", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	_, err := router.GetCertificate(&tls.ClientHelloInfo{ServerName: "attacker.example.net"})

	// ErrCertNotFound rather than ErrorUnknownServerName: the catch-all DID
	// match, the router DID hand the name to the manager, and the manager's
	// allowlist is what refused it. Anything else means this test is passing
	// for the wrong reason.
	assert.ErrorIs(t, err, ErrCertNotFound,
		"a server name outside the allowlist must not receive a certificate")
	assert.Empty(t, obtainer.Calls(), "an unallowlisted server name must cost no ACME order")
}

// Defence in depth for the challenge responder: a token is only ever presented
// for a domain we chose to order, and it answers only that domain's validation
// request.
func TestSANCertManager_HTTPHandler_RefusesTokenForAnotherHost(t *testing.T) {
	manager := testSANCertManager(t)
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	provider := &memoryHTTP01Provider{manager: manager}
	require.NoError(t, provider.Present("app.example.com", "token-1", "key-auth-1"))

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := manager.HTTPHandler(fallback)

	request := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token-1", nil)
	request.Host = "app.example.com"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "key-auth-1", recorder.Body.String())

	// The same token asked for under a different name is not this challenge.
	request = httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token-1", nil)
	request.Host = "attacker.example.net"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusNotFound, recorder.Code,
		"a challenge answers only the domain it was presented for")
}

// The token bucket is the ceiling on distinct domains over time. It has to sit
// under every order -- including the DNS-01 ones the registry used to place
// with no limit at all.
func TestSANCertManager_ProvisionCertificate_IsRateLimited(t *testing.T) {
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.dnsObtainer = obtainer

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	// Drain the bucket so the next order has to wait for a refill.
	for manager.bucket.TryTake() {
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := manager.provisionCertificate(ctx, "app.example.com")

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, obtainer.Calls(), "issuance must wait for a rate limit token")
}

// The issuer and the renewer must draw from the manager's bucket rather than a
// private one, or the paths add up to more orders than the limit allows.
func TestDynamicDomainManager_SharesTheManagersRateLimitBucket(t *testing.T) {
	manager := testSANCertManager(t)
	dm := NewDynamicDomainManager(DynamicDomainConfig{StatePath: t.TempDir() + "/dynamic.state"}, manager, &stubServiceResolver{})

	assert.Same(t, manager.bucket, dm.issuer.bucket)
}

func TestSANCertManager_ObtainCertificate_PrefersDNSWhenConfigured(t *testing.T) {
	manager := testSANCertManager(t)
	dns := successfulObtainer(t)
	httpSolver := successfulObtainer(t)
	manager.dnsObtainer = dns
	manager.httpObtainer = httpSolver

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"app.example.com"}})

	require.NoError(t, err)
	assert.Len(t, dns.Calls(), 1)
	assert.Empty(t, httpSolver.Calls())
}

func TestSANCertManager_ObtainCertificate_FallsBackToHTTPWhenAllowed(t *testing.T) {
	manager := testSANCertManager(t)
	manager.config.HTTPFallback = true

	dns := &fakeObtainer{respond: func(certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, assert.AnError
	}}
	httpSolver := successfulObtainer(t)
	manager.dnsObtainer = dns
	manager.httpObtainer = httpSolver

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"app.example.com"}})

	require.NoError(t, err)
	assert.Len(t, dns.Calls(), 1)
	assert.Len(t, httpSolver.Calls(), 1)
}

func TestSANCertManager_ObtainCertificate_DoesNotFallBackWhenDisabled(t *testing.T) {
	manager := testSANCertManager(t)
	manager.config.HTTPFallback = false

	dns := &fakeObtainer{respond: func(certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, assert.AnError
	}}
	httpSolver := successfulObtainer(t)
	manager.dnsObtainer = dns
	manager.httpObtainer = httpSolver

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"app.example.com"}})

	require.Error(t, err)
	assert.Empty(t, httpSolver.Calls())
}

// A wildcard can only be validated over DNS-01. Without a provider the order
// must be refused rather than sent to a solver that cannot answer it.
func TestSANCertManager_ObtainCertificate_RefusesWildcardWithoutDNS(t *testing.T) {
	manager := testSANCertManager(t)
	httpSolver := successfulObtainer(t)
	manager.httpObtainer = httpSolver

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"*.example.com"}})

	require.Error(t, err)
	assert.Empty(t, httpSolver.Calls())
}

func TestSANCertManager_PlanIssuanceDomains(t *testing.T) {
	tests := []struct {
		name           string
		dnsAvailable   bool
		preferWildcard bool
		domains        []string
		expected       []string
	}{
		{
			name:     "no DNS provider keeps the batch as-is",
			domains:  []string{"a.example.com", "b.example.com", "c.example.com"},
			expected: []string{"a.example.com", "b.example.com", "c.example.com"},
		},
		{
			name:           "DNS provider collapses sibling subdomains into a wildcard",
			dnsAvailable:   true,
			preferWildcard: true,
			domains:        []string{"a.example.com", "b.example.com"},
			expected:       []string{"*.example.com"},
		},
		{
			name:           "the apex rides along, since a wildcard does not cover it",
			dnsAvailable:   true,
			preferWildcard: true,
			domains:        []string{"a.example.com", "b.example.com", "example.com"},
			expected:       []string{"*.example.com", "example.com"},
		},
		{
			name:           "prefer-wildcard off keeps the SAN batch",
			dnsAvailable:   true,
			preferWildcard: false,
			domains:        []string{"a.example.com", "b.example.com"},
			expected:       []string{"a.example.com", "b.example.com"},
		},
		{
			name:           "a single subdomain is not worth a wildcard",
			dnsAvailable:   true,
			preferWildcard: true,
			domains:        []string{"a.example.com"},
			expected:       []string{"a.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := testSANCertManager(t)
			manager.grouper.PreferWildcard = tt.preferWildcard
			manager.grouper.DNSProviderAvailable = tt.dnsAvailable
			if tt.dnsAvailable {
				manager.dnsObtainer = successfulObtainer(t)
			}

			assert.ElementsMatch(t, tt.expected, manager.planIssuanceDomains(tt.domains))
		})
	}
}

// A wildcard certificate has to serve the names it covers, or every handshake
// under it re-orders one.
func TestSANCertManager_GetCertificate_ServesWildcardCoveredDomain(t *testing.T) {
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	cert := testSelfSignedCert(t, []string{"*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	manager.certificates["wildcard"] = &ManagedCert{
		Identifier:  "wildcard",
		Domains:     []string{"*.example.com"},
		NotAfter:    cert.Leaf.NotAfter,
		Certificate: cert,
	}
	manager.domainToCert["*.example.com"] = "wildcard"

	served, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})

	require.NoError(t, err)
	assert.Same(t, cert, served)
	assert.True(t, manager.HasValidCertificate("app.example.com"))

	// A sibling the wildcard already covers is served from what we hold. That
	// is not a hole: the gate is on issuance, and serving a certificate we own
	// costs no ACME order.
	served, err = manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	require.NoError(t, err)
	assert.Same(t, cert, served)

	// ACME wildcards match exactly one label, so this is uncovered -- and
	// unallowlisted, so it is refused rather than ordered.
	_, err = manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "deep.app.example.com"})
	assert.Error(t, err)

	_, err = manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "attacker.example.net"})
	assert.Error(t, err)

	assert.Empty(t, obtainer.Calls(), "no handshake in this test may place an order")
}

// The renewer only keeps certificates whose domains are still allowed. A
// synthesised wildcard is never itself registered, so it has to be allowed by
// way of the registered names it covers -- otherwise it is garbage-collected on
// the first reconcile.
func TestSANCertManager_DomainAllowed_WildcardCoveringAllowedDomain(t *testing.T) {
	manager := testSANCertManager(t)
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))

	assert.True(t, manager.DomainAllowed("*.example.com"))
	assert.False(t, manager.DomainAllowed("*.other.com"))
}

type stubServiceResolver struct{}

func (stubServiceResolver) serviceForName(string) *Service { return nil }
