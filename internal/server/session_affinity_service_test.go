package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAffineService(t *testing.T, options ServiceOptions, bodies ...string) *Router {
	t.Helper()

	router := testRouter(t)

	targets := []string{}
	for _, body := range bodies {
		_, target := testBackend(t, body, http.StatusOK)
		targets = append(targets, target)
	}

	require.NoError(t, router.DeployService("service1", targets, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	return router
}

func sendAffineRequest(t *testing.T, router *Router, cookie *http.Cookie) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w.Result()
}

func TestSessionAffinityService_PinsThroughTheFullRequestPath(t *testing.T) {
	options := defaultServiceOptions
	options.SessionAffinity = true

	router := testAffineService(t, options, "one", "two", "three")

	first := sendAffineRequest(t, router, nil)
	require.Equal(t, http.StatusOK, first.StatusCode)
	require.Len(t, first.Cookies(), 1)

	pin := first.Cookies()[0]
	assert.Equal(t, DefaultSessionAffinityCookieName, pin.Name)

	body := readBody(t, first)
	for range 6 {
		resp := sendAffineRequest(t, router, pin)
		assert.Equal(t, body, readBody(t, resp))
	}
}

// The option rides in ServiceOptions, so a proxy restart has to come back
// pinning. The pins themselves are new, which only re-spreads the clients.
func TestSessionAffinityService_SurvivesAStateRestore(t *testing.T) {
	options := defaultServiceOptions
	options.SessionAffinity = true
	options.SessionAffinityCookieName = "app-instance"

	statePath := filepath.Join(t.TempDir(), "state.json")
	router := NewRouter(statePath)

	_, one := testBackend(t, "one", http.StatusOK)
	_, two := testBackend(t, "two", http.StatusOK)
	require.NoError(t, router.DeployService("service1", []string{one, two}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	restored := NewRouter(statePath)
	require.NoError(t, restored.RestoreLastSavedState())

	resp := sendAffineRequest(t, restored, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, resp.Cookies(), 1)
	assert.Equal(t, "app-instance", resp.Cookies()[0].Name)
}

// A state file written before the option existed must restore to the behaviour
// it had: no pinning, no cookie.
func TestSessionAffinityService_DefaultsOffForOlderState(t *testing.T) {
	router := testAffineService(t, defaultServiceOptions, "one", "two")

	for range 4 {
		resp := sendAffineRequest(t, router, nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Cookies())
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)

	return string(buf[:n])
}
