package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCompressedService(t *testing.T, options ServiceOptions, handler http.HandlerFunc) http.Handler {
	t.Helper()

	router := testRouter(t)
	_, target := testBackendWithHandler(t, handler)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	return testRoutedHandler(t, router)
}

func testCompressionOptions(encodings ...string) ServiceOptions {
	options := defaultServiceOptions
	options.Compression = CompressionOptions{Encodings: encodings}

	return options
}

func testCompressedRequest(t *testing.T, handler http.Handler, url, accept string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, url, nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w.Result()
}

func TestCompressionService_CompressesTargetResponses(t *testing.T) {
	body := strings.Repeat("<p>hello from the app</p>", 200)

	handler := testCompressedService(t, testCompressionOptions(EncodingZstd, EncodingBrotli, EncodingGzip),
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, body)
		})

	resp := testCompressedRequest(t, handler, "http://example.com/", "gzip, br;q=0.5")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, EncodingGzip, resp.Header.Get("Content-Encoding"))
	assert.Equal(t, "Accept-Encoding", resp.Header.Get("Vary"))

	encoded, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Less(t, len(encoded), len(body))
	assert.Equal(t, body, decompress(t, EncodingGzip, encoded))
}

func TestCompressionService_LeavesResponsesAloneWhenDisabled(t *testing.T) {
	body := strings.Repeat("<p>hello from the app</p>", 200)

	handler := testCompressedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	})

	resp := testCompressedRequest(t, handler, "http://example.com/", "gzip")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Empty(t, resp.Header.Get("Content-Encoding"))
	assert.Empty(t, resp.Header.Get("Vary"))

	served, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(served))
}

// The redirect never reaches a target, so this is what proves compression wraps
// the responses the proxy writes itself rather than only what it proxies.
func TestCompressionService_CompressesProxyWrittenResponses(t *testing.T) {
	options := testCompressionOptions(EncodingGzip)
	options.Hosts = []string{"example.com", "www.example.com"}
	options.CanonicalHost = "example.com"
	options.Compression.MinLength = 1

	handler := testCompressedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should not be reached")
	})

	resp := testCompressedRequest(t, handler, "http://www.example.com/", "gzip")
	require.Equal(t, http.StatusMovedPermanently, resp.StatusCode)

	assert.Equal(t, EncodingGzip, resp.Header.Get("Content-Encoding"))

	encoded, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, decompress(t, EncodingGzip, encoded), "http://example.com/")
}

func TestCompressionService_RejectsUnsupportedEncodingsAtDeploy(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "ok", http.StatusOK)

	err := router.DeployService("service1", []string{target}, defaultEmptyReaders,
		testCompressionOptions("gzip", "deflate"), defaultTargetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
	assert.Contains(t, err.Error(), "deflate")
}

func TestCompressionService_SurvivesStateRoundTrip(t *testing.T) {
	options := testCompressionOptions("BROTLI", "gzip")
	options.Compression.MinLength = 256
	options.Compression.ContentTypes = []string{"Text/HTML; charset=utf-8"}

	service := testCreateService(t, options, defaultTargetOptions)
	t.Cleanup(service.Dispose)

	encoded, err := json.Marshal(service)
	require.NoError(t, err)

	var restored Service
	require.NoError(t, json.Unmarshal(encoded, &restored))
	t.Cleanup(restored.Dispose)

	assert.Equal(t, []string{EncodingBrotli, EncodingGzip}, restored.options.Compression.Encodings)
	assert.Equal(t, int64(256), restored.options.Compression.MinLength)
	assert.Equal(t, []string{"text/html"}, restored.options.Compression.ContentTypes)
}

func TestCompressionService_StateWrittenBeforeCompressionExisted(t *testing.T) {
	service := testCreateService(t, defaultServiceOptions, defaultTargetOptions)
	t.Cleanup(service.Dispose)

	encoded, err := json.Marshal(service)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "compression",
		"a service without compression must not add the key to its state file")

	var restored Service
	require.NoError(t, json.Unmarshal(encoded, &restored))
	t.Cleanup(restored.Dispose)

	assert.False(t, restored.options.Compression.Enabled())
}
