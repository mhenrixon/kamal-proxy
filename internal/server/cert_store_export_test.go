package server

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCertStorePaths returns store paths rooted in a fresh temp data dir.
func testCertStorePaths(t testing.TB) CertStorePaths {
	t.Helper()

	dir := t.TempDir()
	return CertStorePaths{
		CertsPath:               filepath.Join(dir, "certs"),
		ACMEStatePath:           filepath.Join(dir, "acme.state"),
		DynamicDomainsStatePath: filepath.Join(dir, "dynamic-domains.state"),
	}
}

// populateCertStore writes one certificate per domain set through the store's
// own write path, plus a matching acme.state, an account key file, and a
// dynamic domains state file.
func populateCertStore(t testing.TB, paths CertStorePaths, domainSets ...[]string) managerState {
	t.Helper()

	state := managerState{
		Certificates: map[string]*ManagedCert{},
		DomainMap:    map[string]string{},
		SavedAt:      time.Now(),
	}

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	for _, domains := range domainSets {
		sorted := sortedCopy(domains)
		resource := testCertResource(t, sorted, time.Now().Add(-time.Hour), notAfter)

		certID := sanCertID(sorted)
		require.NoError(t, writeCertificateFiles(paths.CertsPath, certID, resource.Certificate, resource.PrivateKey))

		state.Certificates[certID] = &ManagedCert{Identifier: certID, Domains: sorted, NotAfter: notAfter}
		for _, domain := range sorted {
			state.DomainMap[domain] = certID
		}
	}

	require.NoError(t, os.MkdirAll(paths.CertsPath, 0700))
	require.NoError(t, writeManagerStateFile(paths.ACMEStatePath, state))
	require.NoError(t, os.WriteFile(filepath.Join(paths.CertsPath, "acme_user.json"),
		testAccountKeyJSON(t), 0600))
	require.NoError(t, os.WriteFile(paths.DynamicDomainsStatePath,
		[]byte(`{"services":{},"quarantine":{},"saved_at":"2026-08-09T00:00:00Z"}`), 0600))

	return state
}

// testAccountKeyJSON builds an acme_user.json with real key material, the way
// saveUser writes it.
func testAccountKeyJSON(t testing.TB) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data, err := json.Marshal(acmeUser{Email: "ops@example.com", KeyPEM: certcrypto.PEMEncode(key)})
	require.NoError(t, err)
	return data
}

// readCertArchive extracts an exported archive into a name -> content map.
func readCertArchive(t testing.TB, path string) map[string][]byte {
	t.Helper()

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	gz, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer gz.Close()

	entries := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		entries[header.Name] = data
	}

	return entries
}

func TestExportCertificateStore_ArchivesTheWholeEstate(t *testing.T) {
	paths := testCertStorePaths(t)
	state := populateCertStore(t, paths, []string{"example.com", "www.example.com"}, []string{"other.test"})

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	summary, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)

	assert.Equal(t, 2, summary.Certificates)
	assert.Equal(t, 3, summary.Domains)
	assert.Empty(t, summary.Warnings)

	entries := readCertArchive(t, outputPath)
	assert.Contains(t, entries, "acme.state")
	assert.Contains(t, entries, "dynamic-domains.state")
	assert.Contains(t, entries, "certs/acme_user.json")
	for certID := range state.Certificates {
		dir := "certs/" + sanitizeFilename(certID)
		assert.Contains(t, entries, dir+"/cert.pem")
		assert.Contains(t, entries, dir+"/key.pem")

		onDisk, err := os.ReadFile(filepath.Join(paths.CertsPath, sanitizeFilename(certID), "cert.pem"))
		require.NoError(t, err)
		assert.Equal(t, onDisk, entries[dir+"/cert.pem"])
	}
	assert.Len(t, entries, 3+2*len(state.Certificates))

	// The archive contains private keys: it must not be world-readable.
	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// The staged write must not leave its temp file behind.
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(outputPath), ".kamal-proxy-cert-export-*"))
	require.NoError(t, err)
	assert.Empty(t, leftovers)
}

func TestExportCertificateStore_EmptyStoreIsAnError(t *testing.T) {
	paths := testCertStorePaths(t)

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	_, err := ExportCertificateStore(paths, outputPath)
	require.ErrorIs(t, err, ErrCertStoreEmpty)

	_, err = os.Stat(outputPath)
	assert.True(t, os.IsNotExist(err), "an empty export must not write an archive")
}

func TestExportCertificateStore_OptionalFilesMayBeMissing(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})
	require.NoError(t, os.Remove(filepath.Join(paths.CertsPath, "acme_user.json")))
	require.NoError(t, os.Remove(paths.DynamicDomainsStatePath))

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	summary, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.Certificates)

	entries := readCertArchive(t, outputPath)
	assert.NotContains(t, entries, "certs/acme_user.json")
	assert.NotContains(t, entries, "dynamic-domains.state")
}

func TestExportCertificateStore_UnparseableStateIsAnError(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})
	require.NoError(t, os.WriteFile(paths.ACMEStatePath, []byte("{torn"), 0600))

	_, err := ExportCertificateStore(paths, filepath.Join(t.TempDir(), "backup.tar.gz"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acme.state")
}

func TestExportCertificateStore_Warnings(t *testing.T) {
	paths := testCertStorePaths(t)
	state := populateCertStore(t, paths, []string{"example.com"}, []string{"gone.test"})

	// A legacy autocert cache, a stray file, and a certificate directory
	// missing from disk should each warn without failing the export.
	require.NoError(t, os.MkdirAll(filepath.Join(paths.CertsPath, "http01"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(paths.CertsPath, "stray.txt"), []byte("x"), 0600))
	goneID := sanCertID([]string{"gone.test"})
	require.NoError(t, os.RemoveAll(filepath.Join(paths.CertsPath, sanitizeFilename(goneID))))

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	summary, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)

	assert.Equal(t, len(state.Certificates), summary.Certificates)
	require.Len(t, summary.Warnings, 3)
	joined := ""
	for _, warning := range summary.Warnings {
		joined += warning + "\n"
	}
	assert.Contains(t, joined, "http01")
	assert.Contains(t, joined, "stray.txt")
	assert.Contains(t, joined, goneID)

	entries := readCertArchive(t, outputPath)
	assert.NotContains(t, entries, "certs/stray.txt")
}

func TestExportCertificateStore_OverwritesAnExistingArchive(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	require.NoError(t, os.WriteFile(outputPath, []byte("old backup"), 0644))

	_, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)

	entries := readCertArchive(t, outputPath)
	assert.Contains(t, entries, "acme.state")

	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestSANCertManager_ExportStoreHoldsTheDiskLock(t *testing.T) {
	manager := testSANCertManager(t)

	resource := testCertResource(t, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	_, err := manager.adoptCertificate(resource, []string{"example.com"})
	require.NoError(t, err)

	paths := CertStorePaths{
		CertsPath:               manager.config.CachePath,
		ACMEStatePath:           manager.config.StatePath,
		DynamicDomainsStatePath: filepath.Join(t.TempDir(), "dynamic-domains.state"),
	}

	// Holding the disk-write lock must block the export until released.
	manager.stateMu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	var summary CertsExportSummary
	go func() {
		close(started)
		var exportErr error
		summary, exportErr = manager.ExportStore(paths, filepath.Join(t.TempDir(), "backup.tar.gz"))
		done <- exportErr
	}()

	<-started
	select {
	case <-done:
		t.Fatal("export completed while the disk-write lock was held")
	case <-time.After(50 * time.Millisecond):
	}

	manager.stateMu.Unlock()
	require.NoError(t, <-done)
	assert.Equal(t, 1, summary.Certificates)
	assert.Equal(t, 1, summary.Domains)
}

func TestExportCertificateStore_InvalidStateIsAnError(t *testing.T) {
	tests := []struct {
		name  string
		state string
	}{
		// A state without its maps would export into an archive the reader
		// rejects, so the export fails instead of producing it.
		{name: "missing maps", state: `{"saved_at":"2026-08-09T00:00:00Z"}`},
		{name: "dangling domain mapping", state: `{"certificates":{},"domain_map":{"a.test":"san:missing"},"saved_at":"2026-08-09T00:00:00Z"}`},
		{name: "null certificate record", state: `{"certificates":{"san:x":null},"domain_map":{},"saved_at":"2026-08-09T00:00:00Z"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := testCertStorePaths(t)
			require.NoError(t, os.MkdirAll(paths.CertsPath, 0700))
			require.NoError(t, os.WriteFile(paths.ACMEStatePath, []byte(tt.state), 0600))

			_, err := ExportCertificateStore(paths, filepath.Join(t.TempDir(), "backup.tar.gz"))
			require.Error(t, err)
		})
	}
}

func TestExportCertificateStore_CertsWithoutStateIsAnError(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})
	require.NoError(t, os.Remove(paths.ACMEStatePath))

	_, err := ExportCertificateStore(paths, filepath.Join(t.TempDir(), "backup.tar.gz"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no state file")
}

func TestExportCertificateStore_SkipsUnparseablePairs(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"}, []string{"broken.test"})

	brokenID := sanitizeFilename(sanCertID([]string{"broken.test"}))
	require.NoError(t, os.WriteFile(filepath.Join(paths.CertsPath, brokenID, "cert.pem"), []byte("not a cert"), 0600))

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	summary, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)

	// Both the skip and the resulting state/disk mismatch warn.
	require.NotEmpty(t, summary.Warnings)
	joined := ""
	for _, warning := range summary.Warnings {
		joined += warning + "\n"
	}
	assert.Contains(t, joined, "does not parse")

	entries := readCertArchive(t, outputPath)
	assert.NotContains(t, entries, "certs/"+brokenID+"/cert.pem")
	assert.NotContains(t, entries, "certs/"+brokenID+"/key.pem")
}

func TestExportCertificateStore_RejectsOutputInsideTheStore(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})

	for _, outputPath := range []string{
		paths.ACMEStatePath,
		paths.DynamicDomainsStatePath,
		filepath.Join(paths.CertsPath, "backup.tar.gz"),
	} {
		_, err := ExportCertificateStore(paths, outputPath)
		require.Error(t, err, "output path %s is inside the store", outputPath)
		assert.Contains(t, err.Error(), "refusing")
	}

	// The store must be untouched afterwards.
	_, err := ExportCertificateStore(paths, filepath.Join(t.TempDir(), "backup.tar.gz"))
	require.NoError(t, err)
}

func TestExportCertificateStore_SkipsInvalidOptionalFiles(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})
	require.NoError(t, os.WriteFile(filepath.Join(paths.CertsPath, "acme_user.json"), []byte("{torn"), 0600))
	require.NoError(t, os.WriteFile(paths.DynamicDomainsStatePath, []byte("{torn"), 0600))

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	summary, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)
	assert.Len(t, summary.Warnings, 2)

	entries := readCertArchive(t, outputPath)
	assert.NotContains(t, entries, "certs/acme_user.json")
	assert.NotContains(t, entries, "dynamic-domains.state")
}

// Guard: the summary type crosses the RPC boundary, so a JSON round-trip (used
// by nothing today, but cheap) and exported fields matter.
func TestCertsExportSummary_RoundTrips(t *testing.T) {
	summary := CertsExportSummary{Certificates: 2, Domains: 5, Warnings: []string{"w"}}
	data, err := json.Marshal(summary)
	require.NoError(t, err)

	var back CertsExportSummary
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, summary, back)
}

func TestExportCertificateStore_AccountKeyOnlyStoreExports(t *testing.T) {
	// A fresh estate that has only registered its ACME account is still worth
	// backing up, and must not trip the certificates-without-state refusal.
	paths := testCertStorePaths(t)
	require.NoError(t, os.MkdirAll(paths.CertsPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(paths.CertsPath, "acme_user.json"), testAccountKeyJSON(t), 0600))

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	summary, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Certificates)

	report, err := VerifyCertificateArchive(outputPath)
	require.NoError(t, err)
	assert.True(t, report.HasAccountKey)
}

func TestExportCertificateStore_RejectsSymlinkedOutputIntoTheStore(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})

	// A symlink pointing at the live state file must not slip past the guard.
	linkPath := filepath.Join(t.TempDir(), "innocent.tar.gz")
	require.NoError(t, os.Symlink(paths.ACMEStatePath, linkPath))

	_, err := ExportCertificateStore(paths, linkPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing")

	// A symlinked directory into the store is refused too.
	linkDir := filepath.Join(t.TempDir(), "linkdir")
	require.NoError(t, os.Symlink(paths.CertsPath, linkDir))

	_, err = ExportCertificateStore(paths, filepath.Join(linkDir, "backup.tar.gz"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing")
}

func TestExportCertificateStore_SurfacesUnrestorableAccountKeyWarning(t *testing.T) {
	// Valid JSON passes the collection pass, but the staged-archive
	// verification knows the reader would refuse to restore it -- the export
	// summary must say so, or the operator learns about the lost ACME
	// identity during a disaster instead of when the backup was taken.
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})
	require.NoError(t, os.WriteFile(filepath.Join(paths.CertsPath, "acme_user.json"),
		[]byte(`{"email":"ops@example.com"}`), 0600))

	summary, err := ExportCertificateStore(paths, filepath.Join(t.TempDir(), "backup.tar.gz"))
	require.NoError(t, err)

	require.NotEmpty(t, summary.Warnings)
	joined := ""
	for _, warning := range summary.Warnings {
		joined += warning + "\n"
	}
	assert.Contains(t, joined, "account key")
}

func TestExportCertificateStore_LongOutputBasename(t *testing.T) {
	// A destination near the filesystem's 255-byte component limit must not
	// fail because the staging file appends to its name.
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})

	longName := strings.Repeat("b", 240) + ".tar.gz"
	outputPath := filepath.Join(t.TempDir(), longName)

	_, err := ExportCertificateStore(paths, outputPath)
	require.NoError(t, err)
	assert.FileExists(t, outputPath)
}

func TestDirInsidePinnedTree(t *testing.T) {
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com"})
	subDir := filepath.Join(paths.CertsPath, sanitizeFilename(sanCertID([]string{"example.com"})))

	for _, target := range []string{paths.CertsPath, subDir} {
		info, err := os.Stat(target)
		require.NoError(t, err)

		inside, err := dirInsidePinnedTree(paths.CertsPath, info)
		require.NoError(t, err)
		assert.True(t, inside, "%s is inside the certificate tree", target)
	}

	outsideInfo, err := os.Stat(t.TempDir())
	require.NoError(t, err)
	inside, err := dirInsidePinnedTree(paths.CertsPath, outsideInfo)
	require.NoError(t, err)
	assert.False(t, inside)

	// A tree that does not exist contains nothing.
	inside, err = dirInsidePinnedTree(filepath.Join(t.TempDir(), "nope"), outsideInfo)
	require.NoError(t, err)
	assert.False(t, inside)
}
