package server

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSANCertManager_SetServiceDirectory(t *testing.T) {
	manager := testSANCertManager(t)

	// No override: the run-level directory answers.
	assert.Equal(t, manager.config.Directory, manager.directoryForService("web"))

	manager.SetServiceDirectory("web", LetsEncryptProduction)
	assert.Equal(t, LetsEncryptProduction, manager.directoryForService("web"))
	assert.Equal(t, manager.config.Directory, manager.directoryForService("other"))

	// Setting the run-level directory explicitly is the same as no override.
	manager.SetServiceDirectory("web", manager.config.Directory)
	assert.Equal(t, manager.config.Directory, manager.directoryForService("web"))

	manager.SetServiceDirectory("web", LetsEncryptProduction)
	manager.SetServiceDirectory("web", "")
	assert.Equal(t, manager.config.Directory, manager.directoryForService("web"))
}

func TestSANCertManager_DirectoryForDomains(t *testing.T) {
	manager := testSANCertManager(t)
	manager.SetServiceDirectory("staging-svc", LetsEncryptProduction)

	// The two services own domains under different roots: a wildcard's owner
	// is resolved through the concrete domains it covers, so a fixture where
	// one wildcard covered both services would be ambiguous by construction.
	require.NoError(t, manager.RegisterDomain("registered.example.com", "staging-svc"))
	require.NoError(t, manager.RegisterDomain("default.example.net", "plain-svc"))
	manager.SetDynamicDomains("staging-svc", []string{"dynamic.example.com"})

	tests := []struct {
		name     string
		domains  []string
		expected string
	}{
		{"registered domain follows its service", []string{"registered.example.com"}, LetsEncryptProduction},
		{"dynamic domain follows its service", []string{"dynamic.example.com"}, LetsEncryptProduction},
		{"domain of a service with no override uses the default", []string{"default.example.net"}, manager.config.Directory},
		{"unknown domain falls back to the default", []string{"nobody.example.org"}, manager.config.Directory},
		{"wildcard resolves through a covered domain", []string{"*.example.com"}, LetsEncryptProduction},
		{"first resolvable owner decides", []string{"nobody.example.net", "registered.example.com"}, LetsEncryptProduction},
		{"a concrete owner outranks a wildcard's coverage scan", []string{"*.example.com", "default.example.net"}, manager.config.Directory},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, manager.directoryForDomains(tt.domains))
		})
	}
}

func TestSANCertManager_RegisteredDomainsTrackTheirOwner(t *testing.T) {
	manager := testSANCertManager(t)

	require.NoError(t, manager.RegisterDomain("app.example.com", "web"))

	service, ok := manager.ownerOf("app.example.com")
	require.True(t, ok)
	assert.Equal(t, "web", service)

	require.NoError(t, manager.UnregisterDomain("app.example.com", "web"))
	_, ok = manager.ownerOf("app.example.com")
	assert.False(t, ok)
}

func TestSANCertManager_AccountFileForDirectory(t *testing.T) {
	manager := testSANCertManager(t) // config.Directory is LetsEncryptStaging here

	tests := []struct {
		name      string
		directory string
		expected  string
	}{
		{"run-level directory keeps the original file", manager.config.Directory, "acme_user.json"},
		{"well-known staging gets a readable name", "https://acme-staging-v02.api.letsencrypt.org/directory", "acme_user.json"},
		{"production override gets its own file", LetsEncryptProduction, "acme_user_5e76d315.json"},
		{"any other directory is keyed by URL hash", "https://acme.example.com/directory", "acme_user_05e6df34.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, manager.accountFileForDirectory(tt.directory))
		})
	}
}

func TestSANCertManager_AccountFileForStagingWhenDefaultIsProduction(t *testing.T) {
	manager := testSANCertManager(t)
	manager.config.Directory = LetsEncryptProduction

	assert.Equal(t, "acme_user.json", manager.accountFileForDirectory(LetsEncryptProduction))
	assert.Equal(t, "acme_user_staging.json", manager.accountFileForDirectory(LetsEncryptStaging))
}

func TestSANCertManager_CertDirectoryMismatched(t *testing.T) {
	manager := testSANCertManager(t)
	manager.SetServiceDirectory("staging-svc", LetsEncryptProduction)
	require.NoError(t, manager.RegisterDomain("app.example.com", "staging-svc"))
	require.NoError(t, manager.RegisterDomain("plain.example.net", "plain-svc"))

	matching := &ManagedCert{Domains: []string{"app.example.com"}, Directory: LetsEncryptProduction}
	assert.False(t, manager.certDirectoryMismatched(matching))

	legacy := &ManagedCert{Domains: []string{"app.example.com"}}
	assert.True(t, manager.certDirectoryMismatched(legacy),
		"an empty recorded directory reads as the run-level one, which this owner has moved away from")

	// A legacy multi-service SAN: the plain domain matches the recorded
	// directory, but ANY mismatched owner flags the certificate — a single
	// first-owner answer would let the staged domain ride the wrong identity.
	mixed := &ManagedCert{Domains: []string{"plain.example.net", "app.example.com"}}
	assert.True(t, manager.certDirectoryMismatched(mixed))

	orphan := &ManagedCert{Domains: []string{"gone.example.org"}, Directory: LetsEncryptProduction}
	assert.False(t, manager.certDirectoryMismatched(orphan),
		"a certificate with no resolvable owner keeps its recorded directory")
}

func TestSANCertManager_WildcardOwnerConsultsOnlyDomainsTheCertServes(t *testing.T) {
	manager := testSANCertManager(t)
	manager.SetServiceDirectory("staged-svc", LetsEncryptProduction)

	wildcard := testSelfSignedCert(t, []string{"*.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	managed := &ManagedCert{
		Identifier:  "wildcard",
		Domains:     []string{"*.example.com"},
		NotAfter:    wildcard.Leaf.NotAfter,
		Certificate: wildcard,
	}
	manager.certificates["wildcard"] = managed
	manager.domainToCert["*.example.com"] = "wildcard"

	// A member riding the wildcard anchors its directory.
	require.NoError(t, manager.RegisterDomain("member.example.com", "plain-svc"))
	assert.False(t, manager.certDirectoryMismatched(managed))

	// A staged host under the same apex goes pending for its own certificate;
	// it must NOT drag the wildcard onto its directory.
	require.NoError(t, manager.RegisterDomain("app.example.com", "staged-svc"))
	_, pending := manager.pendingDomains["app.example.com"]
	require.True(t, pending)
	assert.False(t, manager.certDirectoryMismatched(managed),
		"a pending covered domain must not speak for the wildcard certificate")
}

func TestSANCertManager_AdoptCertificateStampsDirectory(t *testing.T) {
	manager := testSANCertManager(t)
	manager.SetServiceDirectory("prod-svc", LetsEncryptProduction)
	require.NoError(t, manager.RegisterDomain("app.example.com", "prod-svc"))
	require.NoError(t, manager.RegisterDomain("plain.example.com", "plain-svc"))

	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)

	overridden, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, notBefore, notAfter), []string{"app.example.com"})
	require.NoError(t, err)
	assert.Equal(t, LetsEncryptProduction, overridden.Directory)

	plain, err := manager.adoptCertificate(
		testCertResource(t, []string{"plain.example.com"}, notBefore, notAfter), []string{"plain.example.com"})
	require.NoError(t, err)
	assert.Equal(t, manager.config.Directory, plain.Directory)
}

func TestSANCertManager_StateRoundTripsDirectory(t *testing.T) {
	manager := testSANCertManager(t)
	manager.SetServiceDirectory("prod-svc", LetsEncryptProduction)
	require.NoError(t, manager.RegisterDomain("app.example.com", "prod-svc"))

	_, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	reloaded, err := NewSANCertManager(manager.config)
	require.NoError(t, err)
	require.NoError(t, reloaded.loadState())

	certID := reloaded.domainToCert["app.example.com"]
	require.NotEmpty(t, certID)
	assert.Equal(t, LetsEncryptProduction, reloaded.certificates[certID].Directory)
}

func TestSANCertManager_OldStateWithoutDirectoryLoadsAsDefault(t *testing.T) {
	manager := testSANCertManager(t)

	legacy := `{"certificates":{"legacy.example.com":{"identifier":"legacy.example.com","domains":["legacy.example.com"],"not_after":"2030-01-01T00:00:00Z"}},"domain_map":{"legacy.example.com":"legacy.example.com"}}`
	require.NoError(t, os.WriteFile(manager.config.StatePath, []byte(legacy), 0600))

	require.NoError(t, manager.loadState())

	cert := manager.certificates["legacy.example.com"]
	require.NotNil(t, cert)
	assert.Empty(t, cert.Directory)
	assert.Equal(t, manager.config.Directory, manager.normalizeDirectory(cert.Directory))
}

func TestSANCertManager_ObtainCertificateUsesTheOwnersDirectory(t *testing.T) {
	manager := testSANCertManager(t)
	defaultObtainer := successfulObtainer(t)
	manager.httpObtainer = defaultObtainer

	prodObtainer := successfulObtainer(t)
	manager.directoryClients[LetsEncryptProduction] = &directoryClients{httpObtainer: prodObtainer}

	manager.SetServiceDirectory("prod-svc", LetsEncryptProduction)
	require.NoError(t, manager.RegisterDomain("prod.example.com", "prod-svc"))
	require.NoError(t, manager.RegisterDomain("plain.example.com", "plain-svc"))

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"prod.example.com"}})
	require.NoError(t, err)
	assert.Len(t, prodObtainer.Calls(), 1, "the overridden service's order must use its own directory")
	assert.Empty(t, defaultObtainer.Calls())

	_, err = manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"plain.example.com"}})
	require.NoError(t, err)
	assert.Len(t, defaultObtainer.Calls(), 1, "a service without an override stays on the run-level directory")
	assert.Len(t, prodObtainer.Calls(), 1)
}

func TestSANCertManager_ObtainCertificatePrefersTheBundlesDNSObtainer(t *testing.T) {
	manager := testSANCertManager(t)
	manager.httpObtainer = successfulObtainer(t)

	bundleDNS := successfulObtainer(t)
	bundleHTTP := successfulObtainer(t)
	manager.directoryClients[LetsEncryptProduction] = &directoryClients{
		httpObtainer: bundleHTTP,
		dnsObtainer:  bundleDNS,
	}

	manager.SetServiceDirectory("prod-svc", LetsEncryptProduction)
	require.NoError(t, manager.RegisterDomain("prod.example.com", "prod-svc"))

	_, err := manager.obtainCertificate(certificate.ObtainRequest{Domains: []string{"prod.example.com"}})
	require.NoError(t, err)
	assert.Len(t, bundleDNS.Calls(), 1, "a bundle with a DNS solver answers over DNS-01 first")
	assert.Empty(t, bundleHTTP.Calls())
}

func TestSANCertManager_HandshakeBatchNeverMixesDirectories(t *testing.T) {
	manager := testSANCertManager(t)
	defaultObtainer := successfulObtainer(t)
	manager.httpObtainer = defaultObtainer

	prodObtainer := successfulObtainer(t)
	manager.directoryClients[LetsEncryptProduction] = &directoryClients{httpObtainer: prodObtainer}

	manager.SetServiceDirectory("prod-svc", LetsEncryptProduction)
	require.NoError(t, manager.RegisterDomain("plain-a.example.com", "plain-svc"))
	require.NoError(t, manager.RegisterDomain("plain-b.example.com", "plain-svc"))
	require.NoError(t, manager.RegisterDomain("prod.example.com", "prod-svc"))

	_, err := manager.provisionCertificate(context.Background(), "plain-a.example.com")
	require.NoError(t, err)

	require.Len(t, defaultObtainer.Calls(), 1)
	ordered := defaultObtainer.Calls()[0].Domains
	assert.ElementsMatch(t, []string{"plain-a.example.com", "plain-b.example.com"}, ordered,
		"the batch must take same-directory pending mates and leave the overridden service's domain out")
	assert.Empty(t, prodObtainer.Calls())

	// The overridden domain kept its pending slot for a batch of its own.
	_, err = manager.provisionCertificate(context.Background(), "prod.example.com")
	require.NoError(t, err)
	require.Len(t, prodObtainer.Calls(), 1)
	assert.Equal(t, []string{"prod.example.com"}, prodObtainer.Calls()[0].Domains)
}

func TestRouter_DeployRegistersServiceDirectoryWithSANManager(t *testing.T) {
	router := testRouter(t)
	manager := testSANCertManager(t)
	router.SetSANCertManager(manager)

	_, target := testBackend(t, "first", http.StatusOK)

	serviceOptions := defaultServiceOptions
	serviceOptions.TLSEnabled = true
	serviceOptions.Hosts = []string{"app.example.com"}
	serviceOptions.ACMEDirectory = LetsEncryptProduction

	require.NoError(t, router.DeployService("web", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	assert.Equal(t, LetsEncryptProduction, manager.directoryForService("web"),
		"a deploy with --tls-staging (a per-service directory) must reach the shared SAN manager")

	// Redeploying without the override clears it.
	serviceOptions.ACMEDirectory = ""
	require.NoError(t, router.DeployService("web", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	assert.Equal(t, manager.config.Directory, manager.directoryForService("web"))
}

func TestSANCertManager_RegisterDomainRejectsCoverageFromAnotherDirectory(t *testing.T) {
	manager := testSANCertManager(t)
	manager.SetServiceDirectory("staged-svc", LetsEncryptProduction)

	// A valid wildcard issued at the run-level directory covers both hosts.
	wildcard := testSelfSignedCert(t, []string{"*.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	manager.certificates["wildcard"] = &ManagedCert{
		Identifier:  "wildcard",
		Domains:     []string{"*.example.com"},
		NotAfter:    wildcard.Leaf.NotAfter,
		Certificate: wildcard,
	}
	manager.domainToCert["*.example.com"] = "wildcard"

	require.NoError(t, manager.RegisterDomain("app.example.com", "staged-svc"))

	_, pending := manager.pendingDomains["app.example.com"]
	assert.True(t, pending, "a covering certificate from another directory must not satisfy the registration")
	assert.False(t, manager.HasValidCertificate("app.example.com"),
		"the wrong-directory cover does not count as valid for its owner")

	// A same-directory sibling still takes the fast path.
	require.NoError(t, manager.RegisterDomain("other.example.com", "plain-svc"))
	_, pending = manager.pendingDomains["other.example.com"]
	assert.False(t, pending)
	assert.True(t, manager.HasValidCertificate("other.example.com"))
}

func TestRouter_RedeployOffTheSANManagerClearsTheDirectoryOverride(t *testing.T) {
	router := testRouter(t)
	manager := testSANCertManager(t)
	router.SetSANCertManager(manager)

	_, target := testBackend(t, "first", http.StatusOK)

	serviceOptions := defaultServiceOptions
	serviceOptions.TLSEnabled = true
	serviceOptions.Hosts = []string{"app.example.com"}
	serviceOptions.ACMEDirectory = LetsEncryptProduction

	require.NoError(t, router.DeployService("web", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))
	require.Equal(t, LetsEncryptProduction, manager.directoryForService("web"))

	// Redeploying with a static certificate leaves the shared manager behind;
	// the override must not linger, or retained certificates would keep
	// renewing against the old identity.
	certPath, keyPath := prepareTestCertificateFiles(t)
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath

	require.NoError(t, router.DeployService("web", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	assert.Equal(t, manager.config.Directory, manager.directoryForService("web"))
}

func TestIsExtraAccountKeyFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"acme_user_staging.json", true},
		{"acme_user_5e76d315.json", true},
		{"acme_user_05e6df34.json", true},
		{"acme_user.json", false},
		{"acme_user_.json", false},
		{"acme_user_5e76d31.json", false},   // 7 hex chars
		{"acme_user_5e76d3155.json", false}, // 9 hex chars
		{"acme_user_5E76D315.json", false},  // uppercase
		{"acme_user_evil.json", false},
		{"acme_user_staging.json.bak", false},
		{"acme_user_deadbeef.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isExtraAccountKeyFile(tt.name))
		})
	}
}

// Issue #102: a handshake batch never takes another service's pending hosts —
// the primary domain's certificate lifecycle must not be coupled to hosts its
// operator does not control.
func TestSANCertManager_HandshakeBatchNeverMixesServices(t *testing.T) {
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer

	require.NoError(t, manager.RegisterDomain("a.svc-one.test", "svc-one"))
	require.NoError(t, manager.RegisterDomain("b.svc-one.test", "svc-one"))
	require.NoError(t, manager.RegisterDomain("c.svc-two.test", "svc-two"))

	_, err := manager.provisionCertificate(context.Background(), "a.svc-one.test")
	require.NoError(t, err)

	require.Len(t, obtainer.Calls(), 1)
	assert.ElementsMatch(t, []string{"a.svc-one.test", "b.svc-one.test"}, obtainer.Calls()[0].Domains,
		"the batch must take same-service mates and leave other services' hosts out")

	// The other service's host kept its pending slot for a batch of its own.
	_, err = manager.provisionCertificate(context.Background(), "c.svc-two.test")
	require.NoError(t, err)
	require.Len(t, obtainer.Calls(), 2)
	assert.Equal(t, []string{"c.svc-two.test"}, obtainer.Calls()[1].Domains)
}

// A handshake must not wait out another service's in-flight order — that
// order will never cover this domain, and the waiter would fail spuriously
// instead of placing its own service's batch.
func TestSANCertManager_HandshakeDoesNotWaitOnAnotherServicesOrder(t *testing.T) {
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer

	require.NoError(t, manager.RegisterDomain("a.svc-one.test", "svc-one"))
	require.NoError(t, manager.RegisterDomain("c.svc-two.test", "svc-two"))

	// Simulate service one's order having run under the old global slot: a
	// completed unrelated batch must not satisfy — or fail — service two.
	stale := make(chan struct{})
	close(stale)
	manager.mu.Lock()
	manager.provisioning["_batch_"] = stale
	manager.mu.Unlock()

	cert, err := manager.provisionCertificate(context.Background(), "c.svc-two.test")

	require.NoError(t, err, "service two must place its own order, not inherit another's outcome")
	require.NotNil(t, cert)
	require.Len(t, obtainer.Calls(), 1)
	assert.ElementsMatch(t, []string{"c.svc-two.test"}, obtainer.Calls()[0].Domains)
}
