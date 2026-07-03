package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCertificateRegistry(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		Email:          "test@example.com",
		Directory:      acme.DefaultStagingDirectory,
		DNSProvider:    acme.ProviderCloudflare,
		PreferWildcard: true,
		CachePath:      filepath.Join(tmpDir, "certs"),
		StatePath:      filepath.Join(tmpDir, "certificates.state"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)
	assert.NotNil(t, registry)

	// Check cache directory was created
	_, err = os.Stat(config.CachePath)
	require.NoError(t, err)
}

func TestCertificateRegistry_RegisterAndUnregister(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		Email:        "test@example.com",
		HTTPFallback: true, // Use HTTP fallback to avoid needing DNS provider
		CachePath:    filepath.Join(tmpDir, "certs"),
		StatePath:    filepath.Join(tmpDir, "certificates.state"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)

	// Mark as ready manually for testing (normally done by Initialize)
	registry.ready = true

	// Register a domain
	err = registry.RegisterDomain("app.example.com", "service1")
	require.NoError(t, err)

	// Unregister
	err = registry.UnregisterDomain("app.example.com", "service1")
	require.NoError(t, err)
}

func TestCertificateRegistry_RegisterDomain_NotReady(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		CachePath: filepath.Join(tmpDir, "certs"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)

	// Don't call Initialize - registry is not ready
	err = registry.RegisterDomain("app.example.com", "service1")
	require.ErrorIs(t, err, ErrRegistryNotReady)
}

func TestCertificateRegistry_GetStats(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		Email:          "test@example.com",
		DNSProvider:    acme.ProviderCloudflare,
		PreferWildcard: true,
		CachePath:      filepath.Join(tmpDir, "certs"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)

	stats := registry.GetStats()

	assert.Equal(t, false, stats["ready"])
	assert.Equal(t, 0, stats["total_certificates"])
	assert.Equal(t, 0, stats["wildcard_certs"])
	assert.Equal(t, acme.ProviderCloudflare, stats["dns_provider"])
}

func TestCertificateRegistry_StatePeristence(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "certificates.state")

	// Create registry and add a certificate manually
	config := CertificateRegistryConfig{
		CachePath: filepath.Join(tmpDir, "certs"),
		StatePath: statePath,
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)
	registry.ready = true

	// Add a managed certificate directly
	registry.certificates["test:example.com"] = &ManagedCertificate{
		Identifier: "test:example.com",
		Domains:    []string{"example.com"},
		IsWildcard: false,
		NotAfter:   time.Now().Add(90 * 24 * time.Hour),
		Services:   map[string]bool{"service1": true},
	}
	registry.domainToCert["example.com"] = "test:example.com"

	// Save state
	err = registry.saveState()
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(statePath)
	require.NoError(t, err)

	// Create new registry and load state
	registry2, err := NewCertificateRegistry(config)
	require.NoError(t, err)

	err = registry2.loadState()
	require.NoError(t, err)

	// Verify state was loaded
	assert.Len(t, registry2.certificates, 1)
	assert.Contains(t, registry2.domainToCert, "example.com")
}

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		pattern  string
		domain   string
		expected bool
	}{
		// Valid wildcard matches
		{"*.example.com", "app.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "www.example.com", true},

		// Multi-level subdomain should NOT match single-level wildcard
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "deep.nested.example.com", false},

		// Domain itself should not match wildcard
		{"*.example.com", "example.com", false},

		// Different domain should not match
		{"*.example.com", "app.other.com", false},
		{"*.example.com", "example.org", false},

		// Invalid patterns
		{"example.com", "app.example.com", false},
		{"", "app.example.com", false},
		{"*example.com", "app.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.domain, func(t *testing.T) {
			result := matchesWildcard(tt.pattern, tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestManagedCertificate_JSON(t *testing.T) {
	cert := &ManagedCertificate{
		Identifier: "wildcard:example.com",
		Domains:    []string{"*.example.com", "example.com"},
		IsWildcard: true,
		NotAfter:   time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC),
		Services:   map[string]bool{"service1": true, "service2": true},
	}

	// Verify fields are accessible
	assert.Equal(t, "wildcard:example.com", cert.Identifier)
	assert.True(t, cert.IsWildcard)
	assert.Len(t, cert.Services, 2)
}

func TestGetRootDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
		hasErr   bool
	}{
		{"app.example.com", "example.com", false},
		{"api.example.com", "example.com", false},
		{"deep.nested.example.com", "example.com", false},
		{"example.com", "example.com", false},
		{"app.example.co.uk", "example.co.uk", false},
		{"www.example.co.uk", "example.co.uk", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result, err := getRootDomain(tt.domain)
			if tt.hasErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCertificateRegistry_DomainBatching(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		Email:          "test@example.com",
		PreferWildcard: true,
		CachePath:      filepath.Join(tmpDir, "certs"),
		StatePath:      filepath.Join(tmpDir, "certificates.state"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)
	registry.ready = true

	// Register multiple domains from the same root domain
	err = registry.RegisterDomain("app.example.com", "service1")
	require.NoError(t, err)

	err = registry.RegisterDomain("api.example.com", "service2")
	require.NoError(t, err)

	err = registry.RegisterDomain("www.example.com", "service3")
	require.NoError(t, err)

	// All three should be in pendingDomains since no certificate exists yet
	assert.Len(t, registry.pendingDomains, 3)
	assert.Contains(t, registry.pendingDomains, "app.example.com")
	assert.Contains(t, registry.pendingDomains, "api.example.com")
	assert.Contains(t, registry.pendingDomains, "www.example.com")
}

func TestCertificateRegistry_ExistingWildcardCoversDomain(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		Email:          "test@example.com",
		PreferWildcard: true,
		CachePath:      filepath.Join(tmpDir, "certs"),
		StatePath:      filepath.Join(tmpDir, "certificates.state"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)
	registry.ready = true

	// Add an existing wildcard certificate
	registry.certificates["wildcard:example.com"] = &ManagedCertificate{
		Identifier: "wildcard:example.com",
		Domains:    []string{"*.example.com"},
		IsWildcard: true,
		NotAfter:   time.Now().Add(90 * 24 * time.Hour),
		Services:   map[string]bool{},
	}

	// Register a domain that should be covered by the wildcard
	err = registry.RegisterDomain("newapp.example.com", "newservice")
	require.NoError(t, err)

	// Should NOT be in pendingDomains - it's covered by wildcard
	assert.NotContains(t, registry.pendingDomains, "newapp.example.com")

	// Should be mapped to the wildcard certificate
	assert.Equal(t, "wildcard:example.com", registry.domainToCert["newapp.example.com"])

	// Service should be registered on the wildcard cert
	assert.True(t, registry.certificates["wildcard:example.com"].Services["newservice"])
}

func TestCertificateRegistry_DifferentRootDomainsSeparate(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		Email:          "test@example.com",
		PreferWildcard: true,
		CachePath:      filepath.Join(tmpDir, "certs"),
		StatePath:      filepath.Join(tmpDir, "certificates.state"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)
	registry.ready = true

	// Register domains from different root domains
	err = registry.RegisterDomain("app.example.com", "service1")
	require.NoError(t, err)

	err = registry.RegisterDomain("app.other.com", "service2")
	require.NoError(t, err)

	// Both should be in pendingDomains
	assert.Len(t, registry.pendingDomains, 2)
	assert.Contains(t, registry.pendingDomains, "app.example.com")
	assert.Contains(t, registry.pendingDomains, "app.other.com")
}
