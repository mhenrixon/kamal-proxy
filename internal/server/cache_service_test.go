package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCachedRouter deploys one service in front of a handler, with a cache store
// installed the way the run command installs it, and returns a counter of how
// many requests actually reached the target.
func testCachedRouter(t *testing.T, options ServiceOptions, handler http.HandlerFunc) (*Router, *atomic.Int64) {
	t.Helper()

	var reached atomic.Int64
	_, target := testBackendWithHandler(t, countingHandler(&reached, handler))

	router := testRouter(t)
	router.SetCacheStore(testMemoryStore(t), CacheLeaseOptions{})

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	return router, &reached
}

// countingHandler counts the requests a target actually served, ignoring the
// health checks the deploy and the load balancer run against it on their own.
func countingHandler(reached *atomic.Int64, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultHealthCheckPath {
			reached.Add(1)
		}
		handler(w, r)
	}
}

func cachedServiceOptions() ServiceOptions {
	options := defaultServiceOptions
	options.Cache = CacheOptions{Enabled: true}

	return options
}

func publicHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(body))
	}
}

func TestCacheService_ServesRepeatRequestsFromTheStore(t *testing.T) {
	router, reached := testCachedRouter(t, cachedServiceOptions(), publicHandler("hello"))

	status, body := sendGETRequest(router, "http://example.com/products")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "hello", body)

	status, body = sendGETRequest(router, "http://example.com/products")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "hello", body)

	assert.Equal(t, int64(1), reached.Load())
}

func TestCacheService_StaysOffWithoutTheOption(t *testing.T) {
	router, reached := testCachedRouter(t, defaultServiceOptions, publicHandler("hello"))

	sendGETRequest(router, "http://example.com/products")
	sendGETRequest(router, "http://example.com/products")

	assert.Equal(t, int64(2), reached.Load())
}

// The cache sits below the credential check, so a warm entry is never a way
// around it. This is the ordering that makes --cache safe to combine with
// --basic-auth at all.
func TestCacheService_NeverAnswersAnUnauthenticatedRequest(t *testing.T) {
	credential, err := EncodeBasicAuthCredential("user", "secret")
	require.NoError(t, err)

	options := cachedServiceOptions()
	options.BasicAuth = credential

	router, reached := testCachedRouter(t, options, publicHandler("secrets"))

	authenticated := httptest.NewRequest(http.MethodGet, "http://example.com/reports", nil)
	authenticated.SetBasicAuth("user", "secret")

	status, body := sendRequest(router, authenticated)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "secrets", body)

	status, body = sendGETRequest(router, "http://example.com/reports")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.NotContains(t, body, "secrets")

	// A second authenticated request is answered from the entry the first one
	// stored. --basic-auth is a single shared credential that the proxy strips
	// once it has checked it, so everyone past the check is the same client as
	// far as the cache is concerned. (Credentials the proxy only forwards, with
	// no --basic-auth configured, keep the request out of the cache entirely --
	// see requestMayUseCache.)
	authenticated = httptest.NewRequest(http.MethodGet, "http://example.com/reports", nil)
	authenticated.SetBasicAuth("user", "secret")
	status, body = sendRequest(router, authenticated)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "secrets", body)

	assert.Equal(t, int64(1), reached.Load())
}

// A service that only forwards credentials, without a --basic-auth check of its
// own, cannot tell one client's authorization from another's -- so nothing it
// returns is ever stored or served from the cache.
func TestCacheService_LeavesForwardedCredentialsOutOfTheCache(t *testing.T) {
	router, reached := testCachedRouter(t, cachedServiceOptions(), publicHandler("secrets"))

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/reports", nil)
		req.Header.Set("Authorization", "Bearer token")

		status, body := sendRequest(router, req)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "secrets", body)
	}

	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheService_NeverAnswersARequestFromABlockedAddress(t *testing.T) {
	options := cachedServiceOptions()
	options.AllowIPs = []string{"192.168.1.0/24"}

	router, _ := testCachedRouter(t, options, publicHandler("hello"))

	allowed := httptest.NewRequest(http.MethodGet, "http://example.com/products", nil)
	allowed.RemoteAddr = "192.168.1.10:1234"
	status, body := sendRequest(router, allowed)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "hello", body)

	blocked := httptest.NewRequest(http.MethodGet, "http://example.com/products", nil)
	blocked.RemoteAddr = "10.0.0.1:1234"
	status, body = sendRequest(router, blocked)
	assert.Equal(t, http.StatusForbidden, status)
	assert.NotEqual(t, "hello", body)
}

// Redirects are resolved before the cache, so a path move still moves a URL
// whose old location happens to be warm.
func TestCacheService_RedirectsBeforeConsultingTheCache(t *testing.T) {
	router, _ := testCachedRouter(t, cachedServiceOptions(), publicHandler("hello"))

	status, _ := sendGETRequest(router, "http://example.com/old")
	require.Equal(t, http.StatusOK, status)

	redirects, err := NewRedirectRules([]string{"/old=/new"})
	require.NoError(t, err)

	options := cachedServiceOptions()
	options.Redirects = redirects
	require.NoError(t, router.DeployService("service1", []string{"127.0.0.1:1"}, defaultEmptyReaders,
		options, defaultTargetOptions, DeploymentOptions{Force: true}))

	status, _ = sendGETRequest(router, "http://example.com/old")
	assert.Equal(t, http.StatusMovedPermanently, status)
}

// Compression wraps the cache, so one stored copy of the identity body serves
// every client at whatever encoding it asked for.
func TestCacheService_CompressesEachClientFromOneStoredEntry(t *testing.T) {
	options := cachedServiceOptions()
	options.Compression = CompressionOptions{Encodings: []string{EncodingGzip}, MinLength: 1}

	router, reached := testCachedRouter(t, options, publicHandler("<p>hello from the app</p>"))
	handler := testRoutedHandler(t, router)

	plain := testCompressedRequest(t, handler, "http://example.com/products", "")
	require.Equal(t, http.StatusOK, plain.StatusCode)
	assert.Empty(t, plain.Header.Get("Content-Encoding"))
	body, err := io.ReadAll(plain.Body)
	require.NoError(t, err)
	assert.Equal(t, "<p>hello from the app</p>", string(body))

	compressed := testCompressedRequest(t, handler, "http://example.com/products", "gzip")
	require.Equal(t, http.StatusOK, compressed.StatusCode)
	assert.Equal(t, EncodingGzip, compressed.Header.Get("Content-Encoding"))
	assert.Equal(t, cacheStatusHit, compressed.Header.Get("X-Cache"))

	encoded, err := io.ReadAll(compressed.Body)
	require.NoError(t, err)
	assert.Equal(t, "<p>hello from the app</p>", decompress(t, EncodingGzip, encoded))

	assert.Equal(t, int64(1), reached.Load(), "one fetch answers both encodings")
}

// A canary is running different code, so its responses must not answer requests
// routed to the stable targets, or the other way round.
func TestCacheService_SeparatesRolloutTraffic(t *testing.T) {
	var stable, rollout atomic.Int64

	_, stableTarget := testBackendWithHandler(t, countingHandler(&stable, publicHandler("stable")))
	_, rolloutTarget := testBackendWithHandler(t, countingHandler(&rollout, publicHandler("rollout")))

	router := testRouter(t)
	router.SetCacheStore(testMemoryStore(t), CacheLeaseOptions{})

	require.NoError(t, router.DeployService("service1", []string{stableTarget}, defaultEmptyReaders,
		cachedServiceOptions(), defaultTargetOptions, defaultDeploymentOptions))
	require.NoError(t, router.SetRolloutTargets("service1", []string{rolloutTarget}, defaultEmptyReaders, defaultDeploymentOptions))
	require.NoError(t, router.SetRolloutSplit("service1", 0, []string{"canary"}))

	inRollout := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/products", nil)
		req.AddCookie(&http.Cookie{Name: RolloutCookieName, Value: "canary"})
		return req
	}

	_, body := sendGETRequest(router, "http://example.com/products")
	assert.Equal(t, "stable", body)

	_, body = sendRequest(router, inRollout())
	assert.Equal(t, "rollout", body, "the canary must not be answered from the stable entry")

	_, body = sendGETRequest(router, "http://example.com/products")
	assert.Equal(t, "stable", body)
	_, body = sendRequest(router, inRollout())
	assert.Equal(t, "rollout", body)

	assert.Equal(t, int64(1), stable.Load())
	assert.Equal(t, int64(1), rollout.Load())
}

func TestRouter_PurgeCache(t *testing.T) {
	router, reached := testCachedRouter(t, cachedServiceOptions(), publicHandler("hello"))

	sendGETRequest(router, "http://example.com/products")
	sendGETRequest(router, "http://example.com/assets/app.css")
	sendGETRequest(router, "http://example.com/products")
	require.Equal(t, int64(2), reached.Load())

	purged, err := router.PurgeCache("service1", "/assets")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)

	sendGETRequest(router, "http://example.com/products")
	assert.Equal(t, int64(2), reached.Load(), "the untouched path stays cached")

	sendGETRequest(router, "http://example.com/assets/app.css")
	assert.Equal(t, int64(3), reached.Load())

	purged, err = router.PurgeCache("service1", "")
	require.NoError(t, err)
	assert.Equal(t, 2, purged)

	sendGETRequest(router, "http://example.com/products")
	assert.Equal(t, int64(4), reached.Load())
}

func TestRouter_PurgeCacheRejectsAnUnknownService(t *testing.T) {
	router, _ := testCachedRouter(t, cachedServiceOptions(), publicHandler("hello"))

	_, err := router.PurgeCache("nope", "")
	assert.ErrorIs(t, err, ErrorServiceNotFound)
}

func TestRouter_PurgeCacheWithoutAStore(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "hello", http.StatusOK)
	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		cachedServiceOptions(), defaultTargetOptions, defaultDeploymentOptions))

	_, err := router.PurgeCache("service1", "")
	assert.ErrorIs(t, err, ErrorCacheNotAvailable)
}

// A service restored from the state file is built before the store exists, so
// installing the store afterwards has to reach the services already there.
func TestRouter_InstallsTheCacheStoreOnRestoredServices(t *testing.T) {
	var reached atomic.Int64
	_, target := testBackendWithHandler(t, countingHandler(&reached, publicHandler("hello")))

	router := testRouter(t)
	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		cachedServiceOptions(), defaultTargetOptions, defaultDeploymentOptions))

	sendGETRequest(router, "http://example.com/products")
	sendGETRequest(router, "http://example.com/products")
	require.Equal(t, int64(2), reached.Load(), "no store means no caching")

	router.SetCacheStore(testMemoryStore(t), CacheLeaseOptions{})

	sendGETRequest(router, "http://example.com/products")
	sendGETRequest(router, "http://example.com/products")
	assert.Equal(t, int64(3), reached.Load())
}
