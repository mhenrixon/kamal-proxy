package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAllowedPeer = "10.0.0.5:44321"
	testDeniedPeer  = "203.0.113.9:44321"
)

// testRestrictedService deploys a service behind an allow list and returns a
// handler wired the way the real server wires one.
func testRestrictedService(t *testing.T, options ServiceOptions, handler http.HandlerFunc) http.Handler {
	t.Helper()

	router := testRouter(t)
	_, target := testBackendWithHandler(t, handler)

	if options.AllowIPs == nil {
		options.AllowIPs = []string{"10.0.0.0/8"}
	}

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	return testRoutedHandler(t, router)
}

func testRequestFromPeer(peer, url string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.RemoteAddr = peer

	return req
}

func TestIPAllowList_EmptyOptionServesEveryone(t *testing.T) {
	options := defaultServiceOptions
	options.AllowIPs = []string{}

	handler := testRestrictedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIPAllowList_AllowsMatchingPeer(t *testing.T) {
	handler := testRestrictedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	resp := testAuthRequest(handler, testRequestFromPeer(testAllowedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", testAuthBody(t, resp))
}

func TestIPAllowList_RejectsNonMatchingPeer(t *testing.T) {
	var reachedTarget atomic.Int64

	handler := testRestrictedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultHealthCheckPath {
			reachedTarget.Add(1)
		}
		w.Write([]byte("secret"))
	})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, reachedTarget.Load(), "the target must never see a denied request")
}

func TestIPAllowList_RejectsSpoofedForwardedHeader(t *testing.T) {
	// The end-to-end form of the anti-regression test: no --trusted-proxy, so a
	// header cannot buy access no matter what it claims.
	handler := testRestrictedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	})

	req := testRequestFromPeer(testDeniedPeer, "http://example.com/")
	req.Header.Add("X-Forwarded-For", "10.0.0.1")
	req.Header.Add("X-Real-IP", "10.0.0.1")

	resp := testAuthRequest(handler, req)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestIPAllowList_RejectsBeforeRedirecting(t *testing.T) {
	// The deliberate inverse of the basic-auth ordering: a 403 solicits nothing,
	// so a denied peer is refused rather than redirected first.
	options := defaultServiceOptions
	options.TLSEnabled = true
	options.TLSRedirect = true
	options.Hosts = []string{"example.com"}

	handler := testRestrictedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
}

func TestIPAllowList_RejectsBeforeChallengingBasicAuth(t *testing.T) {
	options := defaultServiceOptions
	options.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)

	handler := testRestrictedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	// A denied network never learns that the service wants credentials.
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

func TestIPAllowList_ExemptsHealthCheckRequests(t *testing.T) {
	handler := testRestrictedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {})

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{"GET on the health check path", http.MethodGet, DefaultHealthCheckPath, http.StatusOK},
		{"HEAD on the health check path", http.MethodHead, DefaultHealthCheckPath, http.StatusOK},
		{"POST on the health check path", http.MethodPost, DefaultHealthCheckPath, http.StatusForbidden},
		{"any other path", http.MethodGet, "/", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com"+tt.path, nil)
			req.RemoteAddr = testDeniedPeer

			assert.Equal(t, tt.expectedStatus, testAuthRequest(handler, req).StatusCode)
		})
	}
}

func TestIPAllowList_ExemptsInternalRequests(t *testing.T) {
	handler := testRestrictedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	req := testRequestFromPeer(testDeniedPeer, "http://example.com/")
	req = req.WithContext(markInternalRequest(req.Context()))

	assert.Equal(t, http.StatusOK, testAuthRequest(handler, req).StatusCode)
}

func TestIPAllowList_RejectsRootHealthCheckPath(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	options := defaultServiceOptions
	options.AllowIPs = []string{"10.0.0.0/8"}

	targetOptions := defaultTargetOptions
	targetOptions.HealthCheckConfig.Path = "/"

	err := router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, targetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
	require.ErrorContains(t, err, "health-check-path")
}

func TestIPAllowList_DeployRejectsClientIPHeaderWithoutTrustedProxy(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	options := defaultServiceOptions
	options.AllowIPs = []string{"10.0.0.0/8"}
	options.ClientIPHeader = "CF-Connecting-IP"

	err := router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
	require.ErrorContains(t, err, "requires trusted-proxy")
}

func TestIPAllowList_RejectionRendersCustomErrorPage(t *testing.T) {
	pagesDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(pagesDir, "403.html"), []byte("<h1>not from here</h1>"), 0644))

	options := defaultServiceOptions
	options.ErrorPagePath = pagesDir

	handler := testRestrictedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, testAuthBody(t, resp), "not from here")
}

func TestIPAllowList_RejectionSurvivesInterceptErrors(t *testing.T) {
	options := defaultServiceOptions
	options.InterceptErrorStatuses = []int{403, 503}

	handler := testRestrictedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestIPAllowList_StateWrittenBeforeTheOptionStaysUnrestricted(t *testing.T) {
	state := `
	  {
		"name": "my-app",
		"hosts": ["app.example.com"],
		"active_target": "localhost:3000",
		"options": {},
		"target_options": {
		  "health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000},
		  "response_timeout": 30000000000
		},
		"pause_controller": {"state": 0, "stop_message": "", "fail_after": 0},
		"rollout_controller": null
	  }
	`

	var service Service
	require.NoError(t, json.NewDecoder(strings.NewReader(state)).Decode(&service))
	t.Cleanup(service.Dispose)

	// An upgrade must never silently black-hole an existing service.
	assert.Empty(t, service.options.AllowIPs)
	assert.Nil(t, service.allowedIPs)
}

func TestIPAllowList_EmptyStoredListStaysUnrestricted(t *testing.T) {
	state := `
	  {
		"name": "my-app",
		"active_target": "localhost:3000",
		"options": {"allow_ips": []},
		"target_options": {
		  "health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000},
		  "response_timeout": 30000000000
		},
		"pause_controller": {"state": 0, "stop_message": "", "fail_after": 0},
		"rollout_controller": null
	  }
	`

	var service Service
	require.NoError(t, json.NewDecoder(strings.NewReader(state)).Decode(&service))
	t.Cleanup(service.Dispose)

	// An empty list means "no filter", not "deny everyone" -- otherwise a gem
	// emitting an empty array would take every service down.
	assert.Nil(t, service.allowedIPs)
}

func TestIPAllowList_UnreadableStoredEntryFailsClosed(t *testing.T) {
	state := `
	  {
		"name": "my-app",
		"active_target": "localhost:3000",
		"options": {"allow_ips": ["not-an-ip"]},
		"target_options": {
		  "health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000},
		  "response_timeout": 30000000000
		},
		"pause_controller": {"state": 0, "stop_message": "", "fail_after": 0},
		"rollout_controller": null
	  }
	`

	// Decoding must succeed, or one bad entry takes down every other service in
	// the state file.
	var service Service
	require.NoError(t, json.NewDecoder(strings.NewReader(state)).Decode(&service))
	t.Cleanup(service.Dispose)

	require.NotNil(t, service.allowedIPs)
	assert.False(t, service.allowedIPs.permits(parseHostAddr(testAllowedPeer)))
	assert.False(t, service.allowedIPs.permits(parseHostAddr(testDeniedPeer)))
}

func TestIPAllowList_SurvivesStateRoundTrip(t *testing.T) {
	options := defaultServiceOptions
	options.AllowIPs = []string{"10.0.0.0/8"}
	options.TrustedProxies = []string{"172.16.0.0/12"}

	service := testCreateService(t, options, defaultTargetOptions)
	t.Cleanup(service.Dispose)

	encoded, err := json.Marshal(service)
	require.NoError(t, err)

	var restored Service
	require.NoError(t, json.Unmarshal(encoded, &restored))
	t.Cleanup(restored.Dispose)

	require.NotNil(t, restored.allowedIPs)
	assert.True(t, restored.allowedIPs.permits(parseHostAddr(testAllowedPeer)))
	assert.False(t, restored.allowedIPs.permits(parseHostAddr(testDeniedPeer)))
	assert.Equal(t, []string{"172.16.0.0/12"}, restored.options.TrustedProxies)
}

func TestIPAllowList_RedeployWithoutTheFlagRemovesRestriction(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	restricted := defaultServiceOptions
	restricted.AllowIPs = []string{"10.0.0.0/8"}

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		restricted, defaultTargetOptions, defaultDeploymentOptions))

	handler := testRoutedHandler(t, router)
	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

	resp = testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
