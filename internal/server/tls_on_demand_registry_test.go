package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testReadyCertificateRegistry builds a registry that is ready to serve but has
// no provisioning method wired up (Initialize is what installs the solvers), so
// a provisioning attempt is observable through its pending-domain bookkeeping
// without any ACME traffic.
func testReadyCertificateRegistry(t *testing.T) *CertificateRegistry {
	t.Helper()

	tmpDir := t.TempDir()
	registry, err := NewCertificateRegistry(CertificateRegistryConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
		StatePath: filepath.Join(tmpDir, "certificates.state"),
	})
	require.NoError(t, err)

	registry.ready = true
	return registry
}

func testOnDemandRouterWithRegistry(t *testing.T, askHandler http.HandlerFunc) (*Router, *CertificateRegistry, *httptest.Server) {
	t.Helper()

	askServer := httptest.NewServer(askHandler)
	t.Cleanup(askServer.Close)

	router := testRouter(t)
	registry := testReadyCertificateRegistry(t)
	router.SetCertificateRegistry(registry)

	_, target := testBackend(t, "first", http.StatusOK)

	serviceOptions := defaultServiceOptions
	serviceOptions.TLSEnabled = true
	serviceOptions.ACMECachePath = t.TempDir()
	serviceOptions.TLSOnDemandURL = askServer.URL

	require.NoError(t, router.DeployService("ondemand", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	return router, registry, askServer
}

// A service deployed with --tls-on-demand-url owns the issuance decision for
// every host it catches. The certificate registry provisions on lookup, so if
// the router consults it first it issues for hosts the endpoint would deny --
// defeating the gate and exposing the ACME account to unbounded orders driven
// by attacker-chosen SNI.
func TestRouter_GetCertificate_OnDemandServiceGatesRegistryProvisioning(t *testing.T) {
	var asked atomic.Int64

	router, registry, _ := testOnDemandRouterWithRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.WriteHeader(http.StatusForbidden)
	})

	// Shares a root domain with the host requested below. The registry drains
	// every pending domain under a root into the batch as soon as it starts
	// provisioning, so this entry surviving proves it never started.
	registry.pendingDomains["sibling.example.com"] = "other"

	_, err := router.GetCertificate(&tls.ClientHelloInfo{ServerName: "denied.example.com"})
	assert.Error(t, err, "a denied host must not receive a certificate")

	assert.Contains(t, registry.pendingDomains, "sibling.example.com",
		"certificate registry provisioned for a host the on-demand endpoint governs")
	assert.Positive(t, asked.Load(), "the on-demand endpoint decides issuance for hosts the service catches")
}

// Resolving the service ahead of the registry puts a service-map lookup on
// every registry-served handshake, so keep the cost of that path measurable.
func BenchmarkRouter_GetCertificate(b *testing.B) {
	router := NewRouter(filepath.Join(b.TempDir(), "state.json"))

	registry, err := NewCertificateRegistry(CertificateRegistryConfig{
		Email:     "bench@example.com",
		CachePath: filepath.Join(b.TempDir(), "certs"),
		StatePath: filepath.Join(b.TempDir(), "certificates.state"),
	})
	require.NoError(b, err)
	registry.ready = true

	registry.certificates["app"] = &ManagedCertificate{
		Identifier:  "app",
		Domains:     []string{"app.example.com"},
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		Certificate: &tls.Certificate{},
	}
	registry.domainToCert["app.example.com"] = "app"
	router.SetCertificateRegistry(registry)

	router.services.Set(&Service{name: "app", options: normalizedServiceOptions(ServiceOptions{Hosts: []string{"app.example.com"}})})

	hello := &tls.ClientHelloInfo{ServerName: "app.example.com"}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = router.GetCertificate(hello)
	}
}

// Dynamic domains and on-demand TLS both route through the host-less catch-all
// binding. Validation rejects combining them on a single service; across two
// services they must collide at deploy time, because nothing downstream breaks
// the tie -- the winner would fall out of map iteration order.
func TestRouter_DeployService_CatchAllTLSServicesConflict(t *testing.T) {
	router := testRouter(t)

	_, target := testBackend(t, "first", http.StatusOK)

	dynamicOptions := defaultServiceOptions
	dynamicOptions.TLSEnabled = true
	dynamicOptions.ACMECachePath = t.TempDir()
	dynamicOptions.TLSDomainsSource = "/domains"

	require.NoError(t, router.DeployService("dynamic", []string{target}, defaultEmptyReaders,
		dynamicOptions, defaultTargetOptions, defaultDeploymentOptions))

	onDemandOptions := defaultServiceOptions
	onDemandOptions.TLSEnabled = true
	onDemandOptions.ACMECachePath = t.TempDir()
	onDemandOptions.TLSOnDemandURL = "/ask"

	err := router.DeployService("ondemand", []string{target}, defaultEmptyReaders,
		onDemandOptions, defaultTargetOptions, defaultDeploymentOptions)
	assert.Error(t, err, "two catch-all TLS services must not both claim the host-less binding")
}

// The registry stays in charge of hosts that are not routed to an on-demand
// service, so installing an on-demand catch-all must not disable it wholesale.
func TestRouter_GetCertificate_RegistryStillServesHostScopedServices(t *testing.T) {
	router := testRouter(t)
	registry := testReadyCertificateRegistry(t)
	router.SetCertificateRegistry(registry)

	registry.pendingDomains["sibling.example.com"] = "other"

	_, target := testBackend(t, "first", http.StatusOK)

	// A static certificate, so that the fall-through past the registry lands on
	// StaticCertManager. Left to autocert, this test asked Let's Encrypt
	// PRODUCTION for a certificate for app.example.com and blocked for its full
	// five-minute internal timeout -- on its own, 300 of the suite's 320 seconds.
	certPath, keyPath := prepareTestCertificateFiles(t)

	serviceOptions := defaultServiceOptions
	serviceOptions.TLSEnabled = true
	serviceOptions.ACMECachePath = t.TempDir()
	serviceOptions.Hosts = []string{"app.example.com"}
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath

	require.NoError(t, router.DeployService("hostscoped", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	_, err := router.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	assert.NoError(t, err, "the service's own certificate serves the request")

	assert.NotContains(t, registry.pendingDomains, "sibling.example.com",
		"registry should have batched the pending sibling while provisioning")
}
