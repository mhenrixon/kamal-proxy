package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exportedTestArchive populates a store and exports it, returning the archive
// path, the state that was captured, and the source store's paths.
func exportedTestArchive(t testing.TB, domainSets ...[]string) (string, managerState) {
	archivePath, state, _ := exportedTestArchiveWithSource(t, domainSets...)
	return archivePath, state
}

func exportedTestArchiveWithSource(t testing.TB, domainSets ...[]string) (string, managerState, CertStorePaths) {
	t.Helper()

	paths := testCertStorePaths(t)
	state := populateCertStore(t, paths, domainSets...)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	_, err := ExportCertificateStore(paths, archivePath)
	require.NoError(t, err)

	return archivePath, state, paths
}

// writeTestArchive crafts a tar.gz with exactly the given entries, for
// exercising the reader against archives export would never produce.
func writeTestArchive(t testing.TB, path string, entries map[string][]byte) {
	t.Helper()

	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for name, data := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}))
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
}

func TestRestoreCertificateStore_RoundTrip(t *testing.T) {
	archivePath, exported, source := exportedTestArchiveWithSource(t, []string{"example.com", "www.example.com"}, []string{"other.test"})

	target := testCertStorePaths(t)
	summary, err := RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: target})
	require.NoError(t, err)

	assert.Equal(t, 2, summary.Certificates)
	assert.Equal(t, 3, summary.Domains)
	assert.True(t, summary.AccountKeyRestored)
	assert.True(t, summary.DynamicDomainsRestored)

	// The restored store must boot: a manager pointed at it loads every
	// certificate with its key pair.
	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:     "ops@example.com",
		Directory: LetsEncryptStaging,
		CachePath: target.CertsPath,
		StatePath: target.ACMEStatePath,
	})
	require.NoError(t, err)
	require.NoError(t, manager.loadState())

	require.Len(t, manager.certificates, len(exported.Certificates))
	for id, cert := range exported.Certificates {
		restored := manager.certificates[id]
		require.NotNil(t, restored, "certificate %s missing after restore", id)
		assert.Equal(t, cert.Domains, restored.Domains)
		assert.NotNil(t, restored.Certificate, "certificate %s did not load its key pair", id)
	}

	// Account key and dynamic domain state come back byte-for-byte.
	accountKey, err := os.ReadFile(filepath.Join(target.CertsPath, "acme_user.json"))
	require.NoError(t, err)
	sourceKey, err := os.ReadFile(filepath.Join(source.CertsPath, "acme_user.json"))
	require.NoError(t, err)
	assert.Equal(t, sourceKey, accountKey)

	_, err = os.Stat(target.DynamicDomainsStatePath)
	require.NoError(t, err)
}

func TestRestoreCertificateStore_RefusesNonEmptyStore(t *testing.T) {
	archivePath, _ := exportedTestArchive(t, []string{"example.com"})

	tests := []struct {
		name    string
		prepare func(t *testing.T, paths CertStorePaths)
	}{
		{
			name: "existing state file",
			prepare: func(t *testing.T, paths CertStorePaths) {
				require.NoError(t, writeManagerStateFile(paths.ACMEStatePath, managerState{
					Certificates: map[string]*ManagedCert{}, DomainMap: map[string]string{},
				}))
			},
		},
		{
			name: "existing certificate directory",
			prepare: func(t *testing.T, paths CertStorePaths) {
				require.NoError(t, writeCertificateFiles(paths.CertsPath, "san:existing", []byte("cert"), []byte("key")))
			},
		},
		{
			name: "existing dynamic domains state",
			prepare: func(t *testing.T, paths CertStorePaths) {
				require.NoError(t, os.WriteFile(paths.DynamicDomainsStatePath, []byte("{}"), 0600))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := testCertStorePaths(t)
			tt.prepare(t, paths)

			_, err := RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: paths})
			require.ErrorIs(t, err, ErrCertStoreNotEmpty)

			// With Force the same restore proceeds.
			_, err = RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: paths, Force: true})
			require.NoError(t, err)
		})
	}
}

func TestRestoreCertificateStore_EmptyCertsDirIsEmpty(t *testing.T) {
	archivePath, _ := exportedTestArchive(t, []string{"example.com"})

	paths := testCertStorePaths(t)
	require.NoError(t, os.MkdirAll(paths.CertsPath, 0700))

	_, err := RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: paths})
	require.NoError(t, err, "an existing but empty certs directory is not a non-empty store")
}

func TestRestoreCertificateStore_ForceKeepsUnreferencedCertDirs(t *testing.T) {
	archivePath, _ := exportedTestArchive(t, []string{"example.com"})

	paths := testCertStorePaths(t)
	require.NoError(t, writeCertificateFiles(paths.CertsPath, "san:preexisting", []byte("cert"), []byte("key")))

	_, err := RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: paths, Force: true})
	require.NoError(t, err)

	// The old directory survives on disk, orphaned; the restored state does
	// not reference it.
	_, err = os.Stat(filepath.Join(paths.CertsPath, sanitizeFilename("san:preexisting"), "cert.pem"))
	require.NoError(t, err)

	state := readImportedState(t, paths.ACMEStatePath)
	assert.NotContains(t, state.Certificates, "san:preexisting")
}

func TestRestoreCertificateStore_MissingArchive(t *testing.T) {
	_, err := RestoreCertificateStore(CertStoreRestoreOptions{
		ArchivePath: filepath.Join(t.TempDir(), "nope.tar.gz"),
		Paths:       testCertStorePaths(t),
	})
	require.Error(t, err)
}

func TestVerifyCertificateArchive_ReportsDomainsAndExpiries(t *testing.T) {
	// One live and one expired certificate: both report, neither fails
	// verification -- a faithful backup of an expired cert is still a backup.
	paths := testCertStorePaths(t)
	populateCertStore(t, paths, []string{"example.com", "www.example.com"})

	expiredNotAfter := time.Now().Add(-24 * time.Hour)
	expired := testCertResource(t, []string{"expired.test"}, time.Now().Add(-48*time.Hour), expiredNotAfter)
	expiredID := sanCertID([]string{"expired.test"})
	require.NoError(t, writeCertificateFiles(paths.CertsPath, expiredID, expired.Certificate, expired.PrivateKey))
	state := readImportedState(t, paths.ACMEStatePath)
	state.Certificates[expiredID] = &ManagedCert{Identifier: expiredID, Domains: []string{"expired.test"}, NotAfter: expiredNotAfter}
	state.DomainMap["expired.test"] = expiredID
	require.NoError(t, writeManagerStateFile(paths.ACMEStatePath, state))

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	_, err := ExportCertificateStore(paths, archivePath)
	require.NoError(t, err)

	report, err := VerifyCertificateArchive(archivePath)
	require.NoError(t, err)

	require.Len(t, report.Certificates, 2)
	byDomain := map[string]ArchiveCertInfo{}
	for _, cert := range report.Certificates {
		require.NotEmpty(t, cert.Domains)
		byDomain[cert.Domains[0]] = cert
	}

	live := byDomain["example.com"]
	assert.Equal(t, []string{"example.com", "www.example.com"}, live.Domains)
	assert.False(t, live.NotAfter.Before(time.Now()))

	gone := byDomain["expired.test"]
	assert.True(t, gone.NotAfter.Before(time.Now()))

	assert.Equal(t, 3, report.DomainMappings)
	assert.True(t, report.HasAccountKey)
	assert.True(t, report.HasDynamicDomains)
}

func TestVerifyCertificateArchive_RejectsBadArchives(t *testing.T) {
	// A parseable pair to embed in otherwise-broken archives.
	resource := testCertResource(t, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	certID := sanitizeFilename(sanCertID([]string{"example.com"}))
	validState := []byte(`{"certificates":{},"domain_map":{},"saved_at":"2026-08-09T00:00:00Z"}`)

	tests := []struct {
		name    string
		entries map[string][]byte
		errPart string
	}{
		{
			name:    "path traversal",
			entries: map[string][]byte{"../evil": []byte("x"), "acme.state": validState},
			errPart: "entry",
		},
		{
			name:    "absolute path",
			entries: map[string][]byte{"/etc/passwd": []byte("x"), "acme.state": validState},
			errPart: "entry",
		},
		{
			name:    "traversal inside certs",
			entries: map[string][]byte{"certs/../../evil/cert.pem": []byte("x"), "acme.state": validState},
			errPart: "entry",
		},
		{
			name:    "unexpected entry",
			entries: map[string][]byte{"extra.txt": []byte("x"), "acme.state": validState},
			errPart: "entry",
		},
		{
			name: "certificate missing its key",
			entries: map[string][]byte{
				"acme.state":                    validState,
				"certs/" + certID + "/cert.pem": resource.Certificate,
			},
			errPart: "key.pem",
		},
		{
			name: "unparseable certificate pair",
			entries: map[string][]byte{
				"acme.state":                    validState,
				"certs/" + certID + "/cert.pem": []byte("not a cert"),
				"certs/" + certID + "/key.pem":  []byte("not a key"),
			},
			errPart: certID,
		},
		{
			name: "certificates without a state file",
			entries: map[string][]byte{
				"certs/" + certID + "/cert.pem": resource.Certificate,
				"certs/" + certID + "/key.pem":  resource.PrivateKey,
			},
			errPart: "acme.state",
		},
		{
			name:    "unparseable state",
			entries: map[string][]byte{"acme.state": []byte("{torn")},
			errPart: "acme.state",
		},
		{
			name:    "state with a dangling domain mapping",
			entries: map[string][]byte{"acme.state": []byte(`{"certificates":{},"domain_map":{"a.test":"san:missing"},"saved_at":"2026-08-09T00:00:00Z"}`)},
			errPart: "a.test",
		},
		{
			name:    "state with a null certificate record",
			entries: map[string][]byte{"acme.state": []byte(`{"certificates":{"san:x":null},"domain_map":{},"saved_at":"2026-08-09T00:00:00Z"}`)},
			errPart: "null",
		},
		{
			name:    "empty archive",
			entries: map[string][]byte{},
			errPart: "empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
			writeTestArchive(t, archivePath, tt.entries)

			_, err := VerifyCertificateArchive(archivePath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errPart)

			// Restore must refuse the same archives.
			_, err = RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: testCertStorePaths(t)})
			require.Error(t, err)
		})
	}
}

func TestVerifyCertificateArchive_RejectsSymlinkEntries(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")

	file, err := os.Create(archivePath)
	require.NoError(t, err)
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "acme.state", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd",
	}))
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, file.Close())

	_, err = VerifyCertificateArchive(archivePath)
	require.Error(t, err)
}

func TestVerifyCertificateArchive_WarnsOnStateReferencingMissingCert(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	writeTestArchive(t, archivePath, map[string][]byte{
		"acme.state": []byte(`{
			"certificates":{"san:gone":{"identifier":"san:gone","domains":["gone.test"],"not_after":"2027-01-01T00:00:00Z"}},
			"domain_map":{"gone.test":"san:gone"},
			"saved_at":"2026-08-09T00:00:00Z"}`),
	})

	report, err := VerifyCertificateArchive(archivePath)
	require.NoError(t, err)
	require.Len(t, report.Warnings, 1)
	assert.Contains(t, report.Warnings[0], "san:gone")
}

func TestVerifyCertificateArchive_NotAnArchive(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, []byte("not gzip"), 0600))

	_, err := VerifyCertificateArchive(archivePath)
	require.Error(t, err)
}

// stateJSON marshals a managerState for hand-built archives.
func stateJSON(t testing.TB, state managerState) []byte {
	t.Helper()

	data, err := json.Marshal(state)
	require.NoError(t, err)
	return data
}

// resourceLeaf parses the leaf certificate of a test resource.
func resourceLeaf(t testing.TB, certPEM, keyPEM []byte) *x509.Certificate {
	t.Helper()

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	return leaf
}

func TestRestoreCertificateStore_ForceRemovesStaleStateReferencedDirs(t *testing.T) {
	// The archive's state references a certificate whose files the archive
	// does not hold. The target store has a leftover directory under that same
	// identifier: restoring must remove it, or the "will re-order" warning
	// would silently revive the old pair instead.
	staleID := sanCertID([]string{"stale.test"})
	notAfter := time.Now().Add(30 * 24 * time.Hour)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	writeTestArchive(t, archivePath, map[string][]byte{
		"acme.state": stateJSON(t, managerState{
			Certificates: map[string]*ManagedCert{
				staleID: {Identifier: staleID, Domains: []string{"stale.test"}, NotAfter: notAfter},
			},
			DomainMap: map[string]string{"stale.test": staleID},
			SavedAt:   time.Now(),
		}),
	})

	paths := testCertStorePaths(t)
	old := testCertResource(t, []string{"stale.test"}, time.Now().Add(-time.Hour), notAfter)
	require.NoError(t, writeCertificateFiles(paths.CertsPath, staleID, old.Certificate, old.PrivateKey))

	summary, err := RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: paths, Force: true})
	require.NoError(t, err)
	require.NotEmpty(t, summary.Warnings)

	assert.NoDirExists(t, filepath.Join(paths.CertsPath, sanitizeFilename(staleID)),
		"the stale directory must not answer for a certificate the archive does not hold")
}

func TestReadCertStoreArchive_RejectsUnsanitizedDirNames(t *testing.T) {
	// "san:x" sanitizes to "san_x": two spellings, one on-disk path. Only the
	// sanitized form the exporter writes is accepted.
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	writeTestArchive(t, archivePath, map[string][]byte{
		"acme.state":           []byte(`{"certificates":{},"domain_map":{},"saved_at":"2026-08-09T00:00:00Z"}`),
		"certs/san:x/cert.pem": []byte("x"),
		"certs/san:x/key.pem":  []byte("x"),
	})

	_, err := VerifyCertificateArchive(archivePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected archive entry")
}

func TestVerifyCertificateArchive_DropsInvalidAccountKey(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "valid JSON without key material", key: []byte(`{"email":"ops@example.com"}`)},
		{name: "garbage key material", key: []byte(`{"email":"ops@example.com","key_pem":"bm90IGEga2V5"}`)},
		{name: "non-ECDSA key, which loadOrCreateUser would silently discard", key: testRSAAccountKeyJSON(t)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
			writeTestArchive(t, archivePath, map[string][]byte{
				"acme.state":           []byte(`{"certificates":{},"domain_map":{},"saved_at":"2026-08-09T00:00:00Z"}`),
				"certs/acme_user.json": tt.key,
			})

			report, err := VerifyCertificateArchive(archivePath)
			require.NoError(t, err)
			assert.False(t, report.HasAccountKey)
			require.NotEmpty(t, report.Warnings)

			// The restore skips it rather than planting a broken identity.
			summary, err := RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: testCertStorePaths(t)})
			require.NoError(t, err)
			assert.False(t, summary.AccountKeyRestored)
		})
	}
}

func TestVerifyCertificateArchive_RejectsLeafDisagreeingWithState(t *testing.T) {
	resource := testCertResource(t, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	leaf := resourceLeaf(t, resource.Certificate, resource.PrivateKey)
	certID := sanCertID([]string{"example.com"})
	dir := sanitizeFilename(certID)

	tests := []struct {
		name    string
		record  *ManagedCert
		errPart string
	}{
		{
			name:    "state claims a domain the leaf does not cover",
			record:  &ManagedCert{Identifier: certID, Domains: []string{"evil.test", "example.com"}, NotAfter: leaf.NotAfter},
			errPart: "evil.test",
		},
		{
			name:    "state expiry disagrees with the leaf",
			record:  &ManagedCert{Identifier: certID, Domains: []string{"example.com"}, NotAfter: leaf.NotAfter.Add(90 * 24 * time.Hour)},
			errPart: "expires",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domainMap := map[string]string{}
			for _, domain := range tt.record.Domains {
				domainMap[domain] = certID
			}

			archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
			writeTestArchive(t, archivePath, map[string][]byte{
				"acme.state": stateJSON(t, managerState{
					Certificates: map[string]*ManagedCert{certID: tt.record},
					DomainMap:    domainMap,
					SavedAt:      time.Now(),
				}),
				"certs/" + dir + "/cert.pem": resource.Certificate,
				"certs/" + dir + "/key.pem":  resource.PrivateKey,
			})

			_, err := VerifyCertificateArchive(archivePath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errPart)

			_, err = RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: testCertStorePaths(t)})
			require.Error(t, err)
		})
	}
}

func TestVerifyCertificateArchive_RejectsCorruptStateRecords(t *testing.T) {
	tests := []struct {
		name    string
		state   managerState
		errPart string
	}{
		{
			name: "path-special identifier",
			state: managerState{
				Certificates: map[string]*ManagedCert{
					"..": {Identifier: "..", Domains: []string{"a.test"}, NotAfter: time.Now()},
				},
				DomainMap: map[string]string{"a.test": ".."},
			},
			errPart: "safe storage directory",
		},
		{
			name: "identifier disagrees with its map key",
			state: managerState{
				Certificates: map[string]*ManagedCert{
					"san:a": {Identifier: "san:b", Domains: []string{"a.test"}, NotAfter: time.Now()},
				},
				DomainMap: map[string]string{"a.test": "san:a"},
			},
			errPart: "mismatched identifier",
		},
		{
			name: "identifiers colliding after sanitization",
			state: managerState{
				Certificates: map[string]*ManagedCert{
					"san:x": {Identifier: "san:x", Domains: []string{"a.test"}, NotAfter: time.Now()},
					"san_x": {Identifier: "san_x", Domains: []string{"b.test"}, NotAfter: time.Now()},
				},
				DomainMap: map[string]string{"a.test": "san:x", "b.test": "san_x"},
			},
			errPart: "collide",
		},
		{
			name: "domain mapped to a certificate that does not cover it",
			state: managerState{
				Certificates: map[string]*ManagedCert{
					"san:a": {Identifier: "san:a", Domains: []string{"bar.test"}, NotAfter: time.Now()},
				},
				DomainMap: map[string]string{"foo.test": "san:a"},
			},
			errPart: "does not cover",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
			writeTestArchive(t, archivePath, map[string][]byte{
				"acme.state": stateJSON(t, tt.state),
			})

			_, err := VerifyCertificateArchive(archivePath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errPart)

			// The same archive must never reach a restore's RemoveAll.
			_, err = RestoreCertificateStore(CertStoreRestoreOptions{ArchivePath: archivePath, Paths: testCertStorePaths(t)})
			require.Error(t, err)
		})
	}
}

func TestVerifyCertificateArchive_DirectoryOnlyArchiveIsEmpty(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")

	file, err := os.Create(archivePath)
	require.NoError(t, err)
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "certs/", Typeflag: tar.TypeDir, Mode: 0700}))
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, file.Close())

	_, err = VerifyCertificateArchive(archivePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestCappedReader_FailsBeyondTheLimit(t *testing.T) {
	capped := &cappedReader{reader: bytes.NewReader(make([]byte, 100)), remaining: 10}

	_, err := io.ReadAll(capped)
	require.ErrorIs(t, err, errCertArchiveTooLarge)
}

// testRSAAccountKeyJSON builds an acme_user.json holding a valid RSA key --
// parseable, but not the ECDSA key loadOrCreateUser requires.
func testRSAAccountKeyJSON(t testing.TB) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data, err := json.Marshal(acmeUser{Email: "ops@example.com", KeyPEM: certcrypto.PEMEncode(key)})
	require.NoError(t, err)
	return data
}
