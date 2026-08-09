package server

import (
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandHandler_DeployRejectsInvalidServiceOptions(t *testing.T) {
	handler := NewCommandHandler(testRouter(t))

	var result bool
	err := handler.Deploy(DeployArgs{
		ServiceOptions: ServiceOptions{TLSEnabled: true},
	}, &result)

	require.ErrorContains(t, err, "host must be set when using TLS")
	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
}

func TestCommandHandler_DeployRejectsInvalidTargetOptions(t *testing.T) {
	handler := NewCommandHandler(testRouter(t))

	var result bool
	err := handler.Deploy(DeployArgs{
		TargetURLs:    []string{"localhost:3000"},
		TargetOptions: TargetOptions{MaxConnsPerHost: -1},
	}, &result)

	require.ErrorContains(t, err, "target-max-conns cannot be negative")
	require.ErrorIs(t, err, ErrTargetOptionsInvalid)
}

func TestCommandHandler_CachePurge(t *testing.T) {
	router, _ := testCachedRouter(t, cachedServiceOptions(), publicHandler("hello"))
	handler := NewCommandHandler(router)

	sendGETRequest(router, "http://example.com/products")
	sendGETRequest(router, "http://example.com/assets/app.css")

	var purged int
	require.NoError(t, handler.CachePurge(CachePurgeArgs{Service: "service1", PathPrefix: "/assets"}, &purged))
	assert.Equal(t, 1, purged)

	require.NoError(t, handler.CachePurge(CachePurgeArgs{Service: "service1"}, &purged))
	assert.Equal(t, 1, purged)

	// The reply is set even when the call fails, so the CLI never prints a
	// count from a purge that did not happen.
	err := handler.CachePurge(CachePurgeArgs{Service: "nope"}, &purged)
	assert.ErrorIs(t, err, ErrorServiceNotFound)
	assert.Equal(t, 0, purged)
}

func TestCommandHandler_CachePurgeWithoutAStore(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "hello", http.StatusOK)
	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		cachedServiceOptions(), defaultTargetOptions, defaultDeploymentOptions))

	var purged int
	err := NewCommandHandler(router).CachePurge(CachePurgeArgs{Service: "service1"}, &purged)
	assert.ErrorIs(t, err, ErrorCacheNotAvailable)
}

func TestCommandHandler_CacheStats(t *testing.T) {
	router, _ := testCachedRouter(t, cachedServiceOptions(), publicHandler("hello"))
	handler := NewCommandHandler(router)

	sendGETRequest(router, "http://example.com/products")
	sendGETRequest(router, "http://example.com/assets/app.css")

	var stats CacheStats
	require.NoError(t, handler.CacheStats(CacheStatsArgs{}, &stats))

	assert.Equal(t, CacheStoreMemory, stats.Store)
	assert.False(t, stats.Shared)
	assert.Equal(t, int64(2), stats.Local.Entries)
	assert.Nil(t, stats.Server, "a nil pointer has to survive the gob round trip")
	assert.Empty(t, stats.Local.Services)

	require.NoError(t, handler.CacheStats(CacheStatsArgs{Count: true}, &stats))
	require.Len(t, stats.Local.Services, 1)
	assert.Equal(t, "service1", stats.Local.Services[0].Service)
}

func TestCommandHandler_CacheStatsWithoutAStore(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "hello", http.StatusOK)
	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		cachedServiceOptions(), defaultTargetOptions, defaultDeploymentOptions))

	var stats CacheStats
	err := NewCommandHandler(router).CacheStats(CacheStatsArgs{}, &stats)
	assert.ErrorIs(t, err, ErrorCacheNotAvailable)
}

// SetCacheStore writes the store while services are already serving, so both
// readers have to take the lock. Run under -race, this is the proof.
func TestRouter_CacheStatsAndPurgeReadTheStoreUnderTheLock(t *testing.T) {
	router, _ := testCachedRouter(t, cachedServiceOptions(), publicHandler("hello"))

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { router.SetCacheStore(testMemoryStore(t), CacheLeaseOptions{}) })
		wg.Go(func() { _, _ = router.CacheStats(CacheStatsOptions{}) })
		wg.Go(func() { _, _ = router.PurgeCache("service1", "") })
	}
	wg.Wait()
}

func TestCommandHandler_CertsExport(t *testing.T) {
	router := testRouter(t)
	handler := NewCommandHandler(router)

	// Without a running server there is no config to locate the store.
	var summary CertsExportSummary
	err := handler.CertsExport(CertsExportArgs{Path: filepath.Join(t.TempDir(), "backup.tar.gz")}, &summary)
	require.ErrorContains(t, err, "not available")

	// With a server config pointing at a populated data dir, the export runs
	// even without a certificate manager (a proxy started without --acme-email
	// can still hold files worth backing up).
	dataDir := t.TempDir()
	handler.server = &Server{config: &Config{AlternateConfigDir: dataDir}}
	paths := handler.server.config.CertStorePaths()
	populateCertStore(t, paths, []string{"example.com"})

	outputPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	require.NoError(t, handler.CertsExport(CertsExportArgs{Path: outputPath}, &summary))
	assert.Equal(t, 1, summary.Certificates)

	// The summary counts come from acme.state; prove the tarball itself holds
	// the estate, not just that a file appeared.
	entries := readCertArchive(t, outputPath)
	certDir := "certs/" + sanitizeFilename(sanCertID([]string{"example.com"}))
	assert.Contains(t, entries, "acme.state")
	assert.Contains(t, entries, "certs/acme_user.json")
	assert.Contains(t, entries, "dynamic-domains.state")
	assert.Contains(t, entries, certDir+"/cert.pem")
	assert.Contains(t, entries, certDir+"/key.pem")

	// With a manager installed, the export goes through its disk-write lock.
	router.SetSANCertManager(testSANCertManager(t))
	require.NoError(t, handler.CertsExport(CertsExportArgs{Path: outputPath}, &summary))
	assert.Equal(t, 1, summary.Certificates)
}
