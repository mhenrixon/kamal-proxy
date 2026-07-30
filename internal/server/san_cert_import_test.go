package server

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeLegacyAutocertEntry writes a certificate in the layout autocert.DirCache
// used for the deleted registry's HTTP-01 fallback: one file per name, holding
// the private key PEM block followed by the certificate chain.
func writeLegacyAutocertEntry(t testing.TB, dir, name string, domains []string, notAfter time.Time) {
	t.Helper()

	require.NoError(t, os.MkdirAll(dir, 0700))

	cert := testSelfSignedCert(t, domains, time.Now().Add(-time.Hour), notAfter)

	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)

	blob := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	blob = append(blob, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})...)

	require.NoError(t, os.WriteFile(filepath.Join(dir, name), blob, 0600))
}

// A proxy upgrading from v1.0.0.0 has live certificates only in the registry's
// autocert cache. Re-ordering all of them on the first boot would spend the
// account's rate limit on certificates it already holds, so they are adopted
// into the surviving manager's layout instead.
func TestSANCertManager_ImportsLegacyHTTP01Cache(t *testing.T) {
	manager := testSANCertManager(t)
	legacyDir := filepath.Join(manager.config.CachePath, legacyHTTP01CacheDir)

	expiry := time.Now().Add(60 * 24 * time.Hour)
	writeLegacyAutocertEntry(t, legacyDir, "app.example.com", []string{"app.example.com"}, expiry)
	writeLegacyAutocertEntry(t, legacyDir, "stale.example.com", []string{"stale.example.com"}, time.Now().Add(-time.Hour))

	// autocert also parks its account key and in-flight challenge tokens here.
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, "acme_account+key"), []byte("not a certificate"), 0600))

	manager.importLegacyHTTP01Cache()

	assert.True(t, manager.HasValidCertificate("app.example.com"),
		"a still-valid legacy certificate should serve without a new order")
	assert.False(t, manager.HasCertificate("stale.example.com"),
		"an expired legacy certificate is not worth importing")

	// It survives a restart through the manager's own state and cache files.
	require.NoError(t, manager.persistState())

	reopened, err := NewSANCertManager(manager.config)
	require.NoError(t, err)
	require.NoError(t, reopened.loadState())

	assert.True(t, reopened.HasValidCertificate("app.example.com"))

	// The legacy directory is gone once everything usable has been copied out,
	// so stale private keys do not linger.
	_, err = os.Stat(legacyDir)
	assert.True(t, os.IsNotExist(err), "the legacy cache directory should be removed after a clean import")
}

// Importing must not widen the allowlist: an adopted certificate serves only if
// something still routes its domain.
func TestSANCertManager_ImportedCertificateDoesNotWidenTheAllowlist(t *testing.T) {
	manager := testSANCertManager(t)
	legacyDir := filepath.Join(manager.config.CachePath, legacyHTTP01CacheDir)

	writeLegacyAutocertEntry(t, legacyDir, "app.example.com", []string{"app.example.com"},
		time.Now().Add(60*24*time.Hour))

	manager.importLegacyHTTP01Cache()

	assert.False(t, manager.DomainAllowed("app.example.com"))

	_, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	assert.NoError(t, err, "a domain with a cached certificate still serves it")

	_, err = manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	assert.Error(t, err)
}

// A cache directory that is not there at all is the normal case for a fresh
// install and for the second boot after an upgrade.
func TestSANCertManager_ImportsNothingWhenNoLegacyCacheExists(t *testing.T) {
	manager := testSANCertManager(t)

	manager.importLegacyHTTP01Cache()

	assert.Empty(t, manager.ManagedCertificates())
}
