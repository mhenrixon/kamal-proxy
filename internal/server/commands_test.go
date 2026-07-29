package server

import (
	"net/http"
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
