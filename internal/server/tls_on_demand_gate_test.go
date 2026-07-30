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

func testOnDemandRouter(t *testing.T, askHandler http.HandlerFunc) (*Router, *SANCertManager, *httptest.Server) {
	t.Helper()

	askServer := httptest.NewServer(askHandler)
	t.Cleanup(askServer.Close)

	router := testRouter(t)
	manager := testSANCertManager(t)
	router.SetSANCertManager(manager)

	_, target := testBackend(t, "first", http.StatusOK)

	serviceOptions := defaultServiceOptions
	serviceOptions.TLSEnabled = true
	serviceOptions.ACMECachePath = t.TempDir()
	serviceOptions.TLSOnDemandURL = askServer.URL

	require.NoError(t, router.DeployService("ondemand", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	return router, manager, askServer
}

// A service deployed with --tls-on-demand-url owns the issuance decision for
// every host it catches, so its endpoint has to be asked before any shared
// manager looks at the name.
func TestRouter_GetCertificate_OnDemandServiceOwnsItsHosts(t *testing.T) {
	var asked atomic.Int64

	router, manager, _ := testOnDemandRouter(t, func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.WriteHeader(http.StatusForbidden)
	})

	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer
	manager.dnsObtainer = obtainer

	// Registered with the shared manager by another service. If the on-demand
	// service's handshake reached the shared manager, this would be swept into
	// its batch -- which is exactly what must not happen.
	manager.pendingDomains["sibling.example.com"] = "other"

	_, err := router.GetCertificate(&tls.ClientHelloInfo{ServerName: "denied.example.com"})
	assert.Error(t, err, "a denied host must not receive a certificate")

	assert.Positive(t, asked.Load(), "the on-demand endpoint decides issuance for hosts the service catches")
	assert.Contains(t, manager.pendingDomains, "sibling.example.com",
		"the shared manager provisioned for a host the on-demand endpoint governs")
	assert.Empty(t, obtainer.Calls(), "a denied host must cost no ACME order")
}

// A host-scoped service keeps its own certificate manager even while the shared
// SAN manager is installed.
func TestRouter_GetCertificate_HostScopedServiceServesItsOwnCertificate(t *testing.T) {
	router := testRouter(t)
	router.SetSANCertManager(testSANCertManager(t))

	_, target := testBackend(t, "first", http.StatusOK)
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
}

// Resolving the service is the first thing every handshake does, so keep the
// cost of that path measurable.
func BenchmarkRouter_GetCertificate(b *testing.B) {
	router := NewRouter(filepath.Join(b.TempDir(), "state.json"))

	manager := testSANCertManager(b)
	manager.certificates["app"] = &ManagedCert{
		Identifier:  "app",
		Domains:     []string{"app.example.com"},
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		Certificate: &tls.Certificate{},
	}
	manager.domainToCert["app.example.com"] = "app"
	manager.registeredDomains["app.example.com"] = struct{}{}
	router.SetSANCertManager(manager)

	router.services.Set(&Service{
		name:        "app",
		options:     normalizedServiceOptions(ServiceOptions{Hosts: []string{"app.example.com"}}),
		certManager: manager,
	})

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
