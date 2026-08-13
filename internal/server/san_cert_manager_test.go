package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSANCertManager(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		Directory: LetsEncryptStaging,
		CachePath: filepath.Join(tmpDir, "certs"),
		StatePath: filepath.Join(tmpDir, "state.json"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestNewSANCertManager_RequiresEmail(t *testing.T) {
	config := SANCertManagerConfig{}

	_, err := NewSANCertManager(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestNewSANCertManager_DefaultDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)
	assert.Equal(t, LetsEncryptProduction, manager.config.Directory)
}

func TestSANCertManager_RegisterDomain_NotReady(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)

	// Don't initialize - should fail
	err = manager.RegisterDomain("app.example.com", "service1")
	require.ErrorIs(t, err, ErrManagerNotReady)
}

func TestSANCertManager_RegisterDomain_AddsToPending(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)

	// Manually mark as ready for testing
	manager.ready = true

	err = manager.RegisterDomain("app.example.com", "service1")
	require.NoError(t, err)

	assert.Contains(t, manager.pendingDomains, "app.example.com")
	assert.Equal(t, "service1", manager.pendingDomains["app.example.com"])
}

func TestSANCertManager_RegisterMultipleDomains(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)
	manager.ready = true

	// Register multiple domains
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("api.example.com", "service2"))
	require.NoError(t, manager.RegisterDomain("www.example.com", "service3"))

	assert.Len(t, manager.pendingDomains, 3)
}

func TestSANCertManager_RegisterDifferentRootDomains(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)
	manager.ready = true

	// Register domains from completely different root domains
	// All should be batched together (up to 100)
	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	require.NoError(t, manager.RegisterDomain("api.other.org", "service2"))
	require.NoError(t, manager.RegisterDomain("www.mysite.net", "service3"))
	require.NoError(t, manager.RegisterDomain("admin.different.io", "service4"))

	// All 4 should be pending for a single SAN certificate
	assert.Len(t, manager.pendingDomains, 4)
	assert.Contains(t, manager.pendingDomains, "app.example.com")
	assert.Contains(t, manager.pendingDomains, "api.other.org")
	assert.Contains(t, manager.pendingDomains, "www.mysite.net")
	assert.Contains(t, manager.pendingDomains, "admin.different.io")
}

func TestMaxSANsPerCertificate(t *testing.T) {
	// Verify the constant is set correctly
	assert.Equal(t, 100, MaxSANsPerCertificate)
}

func TestSANCertManager_RegisterDomain_ExistingCert(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)
	manager.ready = true

	// Add an existing valid certificate
	manager.certificates["san:example.com"] = &ManagedCert{
		Identifier: "san:example.com",
		Domains:    []string{"app.example.com", "api.example.com"},
		NotAfter:   time.Now().Add(48 * time.Hour),
	}
	manager.domainToCert["app.example.com"] = "san:example.com"
	manager.domainToCert["api.example.com"] = "san:example.com"

	// Register a domain that's already covered
	err = manager.RegisterDomain("app.example.com", "service1")
	require.NoError(t, err)

	// Should not be in pending since it's already covered
	assert.NotContains(t, manager.pendingDomains, "app.example.com")
}

func TestSANCertManager_RegisterDomain_ExpiredCert(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)
	manager.ready = true

	// Add an expired certificate
	manager.certificates["san:example.com"] = &ManagedCert{
		Identifier: "san:example.com",
		Domains:    []string{"app.example.com", "api.example.com"},
		NotAfter:   time.Now().Add(-1 * time.Hour),
	}
	manager.domainToCert["app.example.com"] = "san:example.com"

	// Register a domain covered by the expired cert
	err = manager.RegisterDomain("api.example.com", "service1")
	require.NoError(t, err)

	// Should be in pending since the cert is expired
	assert.Contains(t, manager.pendingDomains, "api.example.com")
}

func TestSANCertManager_HTTPHandler(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)

	// Add a challenge token
	manager.challengeTokens["test-token"] = http01Challenge{domain: "example.com", keyAuth: "test-key-auth"}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback"))
	})

	handler := manager.HTTPHandler(fallback)

	// Test challenge request
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/test-token", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test-key-auth", rec.Body.String())

	// Test unknown token falls through
	req = httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown-token", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "fallback", rec.Body.String())

	// Test non-challenge request falls through
	req = httptest.NewRequest("GET", "/some/other/path", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "fallback", rec.Body.String())
}

func TestSANCertManager_GetStats(t *testing.T) {
	tmpDir := t.TempDir()

	config := SANCertManagerConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	manager, err := NewSANCertManager(config)
	require.NoError(t, err)

	stats := manager.GetStats()

	assert.Equal(t, false, stats["ready"])
	assert.Equal(t, 0, stats["total_certificates"])
	assert.Equal(t, 0, stats["domains_mapped"])
	assert.Equal(t, 0, stats["pending_domains"])
}

func TestSANCertManager_RegisterDomain_TracksRegisteredDomains(t *testing.T) {
	manager := testSANCertManager(t)

	require.NoError(t, manager.RegisterDomain("app.example.com", "service1"))
	assert.Contains(t, manager.registeredDomains, "app.example.com")

	// Domains covered by an existing certificate are still tracked as registered
	manager.certificates["san:covered"] = &ManagedCert{
		Identifier: "san:covered",
		Domains:    []string{"covered.example.com"},
		NotAfter:   time.Now().Add(48 * time.Hour),
	}
	manager.domainToCert["covered.example.com"] = "san:covered"

	require.NoError(t, manager.RegisterDomain("covered.example.com", "service1"))
	assert.Contains(t, manager.registeredDomains, "covered.example.com")

	require.NoError(t, manager.UnregisterDomain("app.example.com", "service1"))
	assert.NotContains(t, manager.registeredDomains, "app.example.com")
}

func TestSANCertManager_RegisterDomain_IgnoresEmptyHost(t *testing.T) {
	manager := testSANCertManager(t)

	// A catch-all service's normalized hosts are [""] — the empty marker must
	// never reach the shared pending batch, or it poisons every SAN order.
	require.NoError(t, manager.RegisterDomain("", "catch-all-service"))
	assert.Empty(t, manager.pendingDomains)
	assert.Empty(t, manager.registeredDomains)
}

func TestSANCertManager_GetCertificate_UnknownSNIRejected(t *testing.T) {
	manager := testSANCertManager(t)

	// An unknown server name must NOT trigger provisioning; the handshake aborts.
	_, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "attacker.example.com"})
	require.ErrorIs(t, err, ErrCertNotFound)

	// Nothing was queued for provisioning as a side effect
	assert.Empty(t, manager.pendingDomains)
	assert.Empty(t, manager.provisioning)
}

func TestSANCertManager_GetCertificate_DynamicDomainWithoutCert(t *testing.T) {
	manager := testSANCertManager(t)

	requested := make(map[string]string)
	manager.SetDynamicCertRequester(func(domain, service string) {
		requested[domain] = service
	})
	manager.SetDynamicDomains("service1", []string{"tenant.example.com"})

	// No cert yet: the handshake fails fast, but issuance is requested
	_, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "tenant.example.com"})
	require.ErrorIs(t, err, ErrCertNotFound)
	assert.Equal(t, "service1", requested["tenant.example.com"])

	// The synchronous provisioning path was not used
	assert.Empty(t, manager.pendingDomains)
	assert.Empty(t, manager.provisioning)
}

func TestSANCertManager_GetCertificate_ServesExistingCertForEvictedDomain(t *testing.T) {
	manager := testSANCertManager(t)

	cert := testSelfSignedCert(t, []string{"gone.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(12*time.Hour))
	manager.certificates["san:gone"] = &ManagedCert{
		Identifier:  "san:gone",
		Domains:     []string{"gone.example.com"},
		NotAfter:    time.Now().Add(12 * time.Hour),
		Certificate: cert,
	}
	manager.domainToCert["gone.example.com"] = "san:gone"

	// Not registered, not dynamic — but still valid: keep serving until renewal drops it
	served, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "gone.example.com"})
	require.NoError(t, err)
	assert.Equal(t, cert, served)
}

func TestSANCertManager_SetDynamicDomains_ReplacesServiceSet(t *testing.T) {
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com"})
	manager.SetDynamicDomains("service2", []string{"c.example.com"})
	manager.SetDynamicDomains("service1", []string{"b.example.com", "d.example.com"})

	assert.ElementsMatch(t, []string{"b.example.com", "d.example.com"}, manager.DynamicDomains("service1"))
	assert.ElementsMatch(t, []string{"c.example.com"}, manager.DynamicDomains("service2"))

	// a.example.com was evicted entirely
	_, isDynamic := manager.dynamicDomains["a.example.com"]
	assert.False(t, isDynamic)
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"san:example.com", "san_example.com"},
		{"simple", "simple"},
		{"with-dash", "with-dash"},
		{"with_underscore", "with_underscore"},
		{"with.dot", "with.dot"},
		{"with/slash", "with_slash"},
		{"with:colon", "with_colon"},
		{"MixedCase123", "MixedCase123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSANCertManager_InitializeAdoptsLegacyCacheWithoutDeadlock is the
// regression test for Initialize holding the manager lock across the legacy
// cache import: adoption takes the store's locks itself, so calling it from
// inside the initialization critical section deadlocked the first boot after
// an upgrade whenever the legacy cache held a certificate.
func TestSANCertManager_InitializeAdoptsLegacyCacheWithoutDeadlock(t *testing.T) {
	// A stub ACME directory: Initialize fetches it when building the lego
	// client, and with a pre-registered account on disk that is the only
	// network round trip. lego insists on HTTPS, so the stub serves TLS and
	// its certificate is trusted via LEGO_CA_CERTIFICATES.
	var directory *httptest.Server
	directory = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// t.Error, not require: this runs on the server's goroutine, where
		// FailNow would kill the handler instead of failing the test.
		if err := json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   directory.URL + "/nonce",
			"newAccount": directory.URL + "/account",
			"newOrder":   directory.URL + "/order",
			"revokeCert": directory.URL + "/revoke",
			"keyChange":  directory.URL + "/keychange",
		}); err != nil {
			t.Error(err)
		}
	}))
	defer directory.Close()

	dir := t.TempDir()

	caPath := filepath.Join(dir, "stub-ca.pem")
	require.NoError(t, os.WriteFile(caPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: directory.Certificate().Raw}), 0600))
	t.Setenv("LEGO_CA_CERTIFICATES", caPath)
	cachePath := filepath.Join(dir, "certs")

	// A registered account on disk, so Initialize skips ACME registration.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	user, err := json.Marshal(acmeUser{
		Email:        "ops@example.com",
		KeyPEM:       certcrypto.PEMEncode(key),
		Registration: &registration.Resource{URI: directory.URL + "/account/1"},
	})
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(cachePath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(cachePath, acmeUserFile), user, 0600))

	// A legacy autocert cache entry: key PEM followed by the chain.
	resource := testCertResource(t, []string{"legacy.test"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	legacyDir := filepath.Join(cachePath, legacyHTTP01CacheDir)
	require.NoError(t, os.MkdirAll(legacyDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, "legacy.test"),
		append(append([]byte{}, resource.PrivateKey...), resource.Certificate...), 0600))

	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:     "ops@example.com",
		Directory: directory.URL,
		CachePath: cachePath,
		StatePath: filepath.Join(dir, "acme.state"),
	})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- manager.Initialize(context.Background()) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("Initialize deadlocked while adopting the legacy certificate cache")
	}

	assert.True(t, manager.HasCertificate("legacy.test"), "the legacy certificate was not adopted")
}

// Issue #101: a registered domain in the last 24h of its certificate's life
// must keep serving the held certificate and replace it in the background —
// not gamble the handshake on a synchronous ACME order.
func TestSANCertManager_GetCertificate_ServesExpiringRegisteredCertAndQueuesReplacement(t *testing.T) {
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer

	requests := [][2]string{}
	manager.SetDynamicCertRequester(func(domain, service string) {
		requests = append(requests, [2]string{domain, service})
	})

	require.NoError(t, manager.RegisterDomain("app.example.com", "web"))
	held, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-89*24*time.Hour), time.Now().Add(2*time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	served, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})

	require.NoError(t, err, "a handshake must not fail while a valid certificate is held")
	assert.Same(t, held.Certificate, served)
	assert.Empty(t, obtainer.Calls(), "no synchronous order may ride the handshake")
	require.Len(t, requests, 1, "a replacement must be queued asynchronously")
	assert.Equal(t, [2]string{"app.example.com", "web"}, requests[0])
}

// An actually expired certificate serves nobody: the synchronous first-issuance
// path remains the right response for a registered domain.
func TestSANCertManager_GetCertificate_ExpiredRegisteredCertReprovisionsSynchronously(t *testing.T) {
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer

	require.NoError(t, manager.RegisterDomain("app.example.com", "web"))
	_, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-90*24*time.Hour), time.Now().Add(-time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	served, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})

	require.NoError(t, err)
	require.NotNil(t, served)
	require.Len(t, obtainer.Calls(), 1, "an expired certificate must be replaced on the spot")
	assert.True(t, served.Leaf.NotAfter.After(time.Now().Add(24*time.Hour)), "the handshake must get the fresh certificate")
}

// A registered domain holding a certificate from the wrong ACME directory
// (post --tls-staging flip) reprovisions synchronously: the mismatch is fresh
// operator intent, not a degraded renewal, and a wrong-CA certificate may be
// untrusted by the clients the flip was made for.
func TestSANCertManager_GetCertificate_MismatchedDirectoryCertReprovisionsSynchronously(t *testing.T) {
	manager := testSANCertManager(t)
	stagingObtainer := successfulObtainer(t)
	manager.httpObtainer = stagingObtainer

	prodObtainer := successfulObtainer(t)
	manager.directoryClients[LetsEncryptProduction] = &directoryClients{httpObtainer: prodObtainer}

	require.NoError(t, manager.RegisterDomain("app.example.com", "staged"))
	held, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	manager.SetServiceDirectory("staged", LetsEncryptProduction)

	served, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})

	require.NoError(t, err)
	require.NotNil(t, served)
	assert.NotSame(t, held.Certificate, served, "the wrong-directory certificate must not keep serving")
	require.Len(t, prodObtainer.Calls(), 1, "the replacement must be ordered at the service's directory")
	assert.Empty(t, stagingObtainer.Calls())
}

// A dynamic domain in the same situation keeps serving: hard-failing every
// tenant handshake while the issuer drains a rate-limited queue would turn
// one --tls-staging flip into a fleet outage.
func TestSANCertManager_GetCertificate_MismatchedDynamicCertServedWhileIssuerReplaces(t *testing.T) {
	manager := testSANCertManager(t)
	obtainer := successfulObtainer(t)
	manager.httpObtainer = obtainer

	requests := []string{}
	manager.SetDynamicCertRequester(func(domain, service string) {
		requests = append(requests, domain)
	})

	manager.SetDynamicDomains("tenants", []string{"shop.tenant.net"})
	held, err := manager.adoptCertificate(
		testCertResource(t, []string{"shop.tenant.net"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)),
		[]string{"shop.tenant.net"})
	require.NoError(t, err)

	manager.SetServiceDirectory("tenants", LetsEncryptProduction)

	served, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "shop.tenant.net"})

	require.NoError(t, err)
	assert.Same(t, held.Certificate, served, "tenant handshakes keep serving while the issuer replaces")
	assert.Empty(t, obtainer.Calls(), "no synchronous order may ride a tenant handshake")
	assert.Equal(t, []string{"shop.tenant.net"}, requests)
}

// A handshake that waits out another handshake's order must not be handed the
// wrong-directory certificate that order failed to replace.
func TestSANCertManager_GetCertificate_WaiterRefusesStillMismatchedCert(t *testing.T) {
	manager := testSANCertManager(t)
	manager.httpObtainer = successfulObtainer(t)

	require.NoError(t, manager.RegisterDomain("app.example.com", "staged"))
	_, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	manager.SetServiceDirectory("staged", LetsEncryptProduction)

	// Occupy the provisioning slot, as a concurrent handshake's order would.
	inflight := make(chan struct{})
	manager.mu.Lock()
	manager.provisioning["_batch_"] = inflight
	manager.mu.Unlock()

	type result struct {
		cert *tls.Certificate
		err  error
	}
	results := make(chan result, 1)
	go func() {
		cert, err := manager.provisionCertificate(context.Background(), "app.example.com")
		results <- result{cert, err}
	}()

	// The order finishes WITHOUT adopting a replacement (it failed).
	close(inflight)

	r := <-results
	require.Error(t, r.err, "the waiter must not serve the certificate the failed order was replacing")
	assert.ErrorIs(t, r.err, ErrCertNotFound)
	assert.Nil(t, r.cert)
}

// Same rule for expiry: after a failed order, the waiter refuses a
// certificate no client would accept rather than moving the failure
// client-side.
func TestSANCertManager_GetCertificate_WaiterRefusesExpiredCert(t *testing.T) {
	manager := testSANCertManager(t)
	manager.httpObtainer = successfulObtainer(t)

	require.NoError(t, manager.RegisterDomain("app.example.com", "web"))
	_, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-90*24*time.Hour), time.Now().Add(-time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	inflight := make(chan struct{})
	manager.mu.Lock()
	manager.provisioning["_batch_"] = inflight
	manager.mu.Unlock()

	type result struct {
		cert *tls.Certificate
		err  error
	}
	results := make(chan result, 1)
	go func() {
		cert, err := manager.provisionCertificate(context.Background(), "app.example.com")
		results <- result{cert, err}
	}()

	close(inflight)

	r := <-results
	require.ErrorIs(t, r.err, ErrCertNotFound)
	assert.Nil(t, r.cert)
}
