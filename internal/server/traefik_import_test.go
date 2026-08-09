package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// traefikCertEntry builds one Certificates[] entry the way Traefik writes it:
// domain metadata plus base64-wrapped PEM for the certificate and its key.
func traefikCertEntry(t testing.TB, domains []string, notBefore, notAfter time.Time) map[string]any {
	t.Helper()

	resource := testCertResource(t, domains, notBefore, notAfter)

	sans := []string{}
	if len(domains) > 1 {
		sans = domains[1:]
	}

	return map[string]any{
		"domain":      map[string]any{"main": domains[0], "sans": sans},
		"certificate": base64.StdEncoding.EncodeToString(resource.Certificate),
		"key":         base64.StdEncoding.EncodeToString(resource.PrivateKey),
		"Store":       "default",
	}
}

// writeTraefikAcme writes an acme.json with the given resolver blocks.
func writeTraefikAcme(t testing.TB, path string, resolvers map[string][]map[string]any) {
	t.Helper()

	file := map[string]any{}
	for name, entries := range resolvers {
		file[name] = map[string]any{
			"Account":      map[string]any{"Email": "ops@example.com"},
			"Certificates": entries,
		}
	}

	data, err := json.Marshal(file)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

// testTraefikImportOptions returns options rooted in a temp data dir, plus the
// acme.json path the fixture should be written to.
func testTraefikImportOptions(t testing.TB) TraefikImportOptions {
	t.Helper()

	dir := t.TempDir()
	return TraefikImportOptions{
		ACMEPath:  filepath.Join(dir, "acme.json"),
		CertsPath: filepath.Join(dir, "certs"),
		StatePath: filepath.Join(dir, "acme.state"),
	}
}

func readImportedState(t testing.TB, path string) managerState {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var state managerState
	require.NoError(t, json.Unmarshal(data, &state))
	return state
}

func TestImportTraefikCertificates_ImportsValidEntries(t *testing.T) {
	opts := testTraefikImportOptions(t)
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour)

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"letsencrypt": {
			traefikCertEntry(t, []string{"app.example.com"}, notBefore, notAfter),
			traefikCertEntry(t, []string{"shop.example.com", "www.shop.example.com"}, notBefore, notAfter),
		},
	})

	summary, err := ImportTraefikCertificates(opts)
	require.NoError(t, err)

	assert.Equal(t, 2, summary.Imported)
	assert.Zero(t, summary.SkippedExpired)
	assert.Zero(t, summary.SkippedDuplicate)
	assert.Zero(t, summary.FailedToParse)

	state := readImportedState(t, opts.StatePath)
	assert.Len(t, state.Certificates, 2)

	for _, domain := range []string{"app.example.com", "shop.example.com", "www.shop.example.com"} {
		certID, ok := state.DomainMap[domain]
		require.True(t, ok, "domain %q should be mapped", domain)

		cert := state.Certificates[certID]
		require.NotNil(t, cert)
		assert.WithinDuration(t, notAfter, cert.NotAfter, 2*time.Second)

		certDir := filepath.Join(opts.CertsPath, sanitizeFilename(certID))
		assert.FileExists(t, filepath.Join(certDir, "cert.pem"))
		assert.FileExists(t, filepath.Join(certDir, "key.pem"))
	}

	// The SAN grouping from the source is preserved as-is.
	shopID := state.DomainMap["shop.example.com"]
	assert.Equal(t, shopID, state.DomainMap["www.shop.example.com"])
	assert.ElementsMatch(t, []string{"shop.example.com", "www.shop.example.com"}, state.Certificates[shopID].Domains)

	// The write is atomic: no torn temp file left behind.
	assert.NoFileExists(t, opts.StatePath+".tmp")
}

// The whole point of the import: the manager boots with the certificates
// already serving, no ACME order needed.
func TestImportTraefikCertificates_StateLoadsIntoSANCertManager(t *testing.T) {
	opts := testTraefikImportOptions(t)

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"letsencrypt": {
			traefikCertEntry(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour)),
		},
	})

	_, err := ImportTraefikCertificates(opts)
	require.NoError(t, err)

	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:     "test@example.com",
		Directory: LetsEncryptStaging,
		CachePath: opts.CertsPath,
		StatePath: opts.StatePath,
	})
	require.NoError(t, err)
	require.NoError(t, manager.loadState())

	assert.True(t, manager.HasValidCertificate("app.example.com"))
}

func TestImportTraefikCertificates_SkipsExpiredAndNotYetValid(t *testing.T) {
	opts := testTraefikImportOptions(t)

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"letsencrypt": {
			traefikCertEntry(t, []string{"expired.example.com"}, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)),
			traefikCertEntry(t, []string{"future.example.com"}, time.Now().Add(24*time.Hour), time.Now().Add(90*24*time.Hour)),
		},
	})

	summary, err := ImportTraefikCertificates(opts)
	require.NoError(t, err)

	assert.Zero(t, summary.Imported)
	assert.Equal(t, 2, summary.SkippedExpired)

	state := readImportedState(t, opts.StatePath)
	assert.Empty(t, state.DomainMap)
	assert.Empty(t, state.Certificates)
}

func TestImportTraefikCertificates_KeepsLongerLivedExistingMapping(t *testing.T) {
	opts := testTraefikImportOptions(t)

	// A cert the proxy already holds, outliving the one Traefik has.
	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:     "test@example.com",
		Directory: LetsEncryptStaging,
		CachePath: opts.CertsPath,
		StatePath: opts.StatePath,
	})
	require.NoError(t, err)
	existing, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"letsencrypt": {
			traefikCertEntry(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)),
		},
	})

	summary, err := ImportTraefikCertificates(opts)
	require.NoError(t, err)

	assert.Zero(t, summary.Imported)
	assert.Equal(t, 1, summary.SkippedDuplicate)

	state := readImportedState(t, opts.StatePath)
	assert.Equal(t, existing.Identifier, state.DomainMap["app.example.com"])
}

func TestImportTraefikCertificates_ReplacesShorterLivedExistingMapping(t *testing.T) {
	opts := testTraefikImportOptions(t)

	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:     "test@example.com",
		Directory: LetsEncryptStaging,
		CachePath: opts.CertsPath,
		StatePath: opts.StatePath,
	})
	require.NoError(t, err)
	existing, err := manager.adoptCertificate(
		testCertResource(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour)),
		[]string{"app.example.com"})
	require.NoError(t, err)

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"letsencrypt": {
			traefikCertEntry(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)),
		},
	})

	summary, err := ImportTraefikCertificates(opts)
	require.NoError(t, err)

	assert.Equal(t, 1, summary.Imported)
	assert.Zero(t, summary.SkippedDuplicate)

	// The identifier is a hash of the domain set, so it does not change -- the
	// certificate behind it does.
	state := readImportedState(t, opts.StatePath)
	require.Equal(t, existing.Identifier, state.DomainMap["app.example.com"])
	assert.WithinDuration(t, time.Now().Add(60*24*time.Hour),
		state.Certificates[state.DomainMap["app.example.com"]].NotAfter, 2*time.Second)

	// The files on disk hold the imported certificate now.
	loaded, err := tls.LoadX509KeyPair(
		filepath.Join(opts.CertsPath, sanitizeFilename(existing.Identifier), "cert.pem"),
		filepath.Join(opts.CertsPath, sanitizeFilename(existing.Identifier), "key.pem"))
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(loaded.Certificate[0])
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(60*24*time.Hour), leaf.NotAfter, 2*time.Second)
}

func TestImportTraefikCertificates_ResolverSelection(t *testing.T) {
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour)

	build := func(t *testing.T) TraefikImportOptions {
		opts := testTraefikImportOptions(t)
		writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
			"letsencrypt": {traefikCertEntry(t, []string{"le.example.com"}, notBefore, notAfter)},
			"zerossl":     {traefikCertEntry(t, []string{"zs.example.com"}, notBefore, notAfter)},
		})
		return opts
	}

	t.Run("a named resolver imports only its own block", func(t *testing.T) {
		opts := build(t)
		opts.Resolver = "letsencrypt"

		summary, err := ImportTraefikCertificates(opts)
		require.NoError(t, err)

		assert.Equal(t, 1, summary.Imported)
		state := readImportedState(t, opts.StatePath)
		assert.Contains(t, state.DomainMap, "le.example.com")
		assert.NotContains(t, state.DomainMap, "zs.example.com")
	})

	t.Run("all resolvers import by default", func(t *testing.T) {
		opts := build(t)

		summary, err := ImportTraefikCertificates(opts)
		require.NoError(t, err)

		assert.Equal(t, 2, summary.Imported)
	})

	t.Run("an unknown resolver is an error", func(t *testing.T) {
		opts := build(t)
		opts.Resolver = "missing"

		_, err := ImportTraefikCertificates(opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing")
	})
}

func TestImportTraefikCertificates_LastResolverWinsPerDomain(t *testing.T) {
	opts := testTraefikImportOptions(t)
	notBefore := time.Now().Add(-time.Hour)

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"alpha": {traefikCertEntry(t, []string{"app.example.com"}, notBefore, time.Now().Add(80*24*time.Hour))},
		"beta":  {traefikCertEntry(t, []string{"app.example.com"}, notBefore, time.Now().Add(40*24*time.Hour))},
	})

	summary, err := ImportTraefikCertificates(opts)
	require.NoError(t, err)

	// Resolvers are visited in sorted order, so "beta" writes last and wins,
	// even though "alpha" holds the longer-lived certificate.
	state := readImportedState(t, opts.StatePath)
	cert := state.Certificates[state.DomainMap["app.example.com"]]
	require.NotNil(t, cert)
	assert.WithinDuration(t, time.Now().Add(40*24*time.Hour), cert.NotAfter, 2*time.Second)

	warnings := strings.Join(summary.Warnings, "\n")
	assert.Contains(t, warnings, "app.example.com")
	assert.Contains(t, warnings, "alpha")
	assert.Contains(t, warnings, "beta")
}

func TestImportTraefikCertificates_WarnsOnWildcardEntries(t *testing.T) {
	opts := testTraefikImportOptions(t)

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"letsencrypt": {
			traefikCertEntry(t, []string{"*.example.com", "example.com"}, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour)),
		},
	})

	summary, err := ImportTraefikCertificates(opts)
	require.NoError(t, err)

	assert.Equal(t, 1, summary.Imported)
	state := readImportedState(t, opts.StatePath)
	assert.Contains(t, state.DomainMap, "*.example.com")

	warnings := strings.Join(summary.Warnings, "\n")
	assert.Contains(t, warnings, "*.example.com")
	assert.Contains(t, warnings, "DNS-01")
}

func TestImportTraefikCertificates_CountsUnparseableEntries(t *testing.T) {
	opts := testTraefikImportOptions(t)

	good := traefikCertEntry(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour))

	badBase64 := traefikCertEntry(t, []string{"b64.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour))
	badBase64["certificate"] = "not-base64!"

	notPEM := map[string]any{
		"domain":      map[string]any{"main": "pem.example.com"},
		"certificate": base64.StdEncoding.EncodeToString([]byte("not a certificate")),
		"key":         base64.StdEncoding.EncodeToString([]byte("not a key")),
	}

	writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
		"letsencrypt": {good, badBase64, notPEM},
	})

	summary, err := ImportTraefikCertificates(opts)
	require.NoError(t, err, "individual bad entries must not abort the import")

	assert.Equal(t, 1, summary.Imported)
	assert.Equal(t, 2, summary.FailedToParse)

	state := readImportedState(t, opts.StatePath)
	assert.Contains(t, state.DomainMap, "app.example.com")
	assert.Len(t, state.DomainMap, 1)
}

func TestImportTraefikCertificates_ErrorsOnBadInput(t *testing.T) {
	t.Run("a missing file is an error", func(t *testing.T) {
		opts := testTraefikImportOptions(t)

		_, err := ImportTraefikCertificates(opts)
		require.Error(t, err)
	})

	t.Run("a wholly unparseable file is an error", func(t *testing.T) {
		opts := testTraefikImportOptions(t)
		require.NoError(t, os.WriteFile(opts.ACMEPath, []byte("{not json"), 0600))

		_, err := ImportTraefikCertificates(opts)
		require.Error(t, err)
	})

	t.Run("a corrupt existing state file is an error, not clobbered", func(t *testing.T) {
		opts := testTraefikImportOptions(t)
		writeTraefikAcme(t, opts.ACMEPath, map[string][]map[string]any{
			"letsencrypt": {traefikCertEntry(t, []string{"app.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour))},
		})
		require.NoError(t, os.WriteFile(opts.StatePath, []byte("{torn"), 0600))

		_, err := ImportTraefikCertificates(opts)
		require.Error(t, err)

		data, readErr := os.ReadFile(opts.StatePath)
		require.NoError(t, readErr)
		assert.Equal(t, "{torn", string(data), "the existing state must survive a refused import")
	})
}
