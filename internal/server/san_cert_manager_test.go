package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

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
	manager.challengeTokens["test-token"] = "test-key-auth"

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
