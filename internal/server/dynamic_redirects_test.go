package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceOptions_ValidateDynamicRedirects(t *testing.T) {
	tests := []struct {
		name     string
		options  ServiceOptions
		errorMsg string
	}{
		{
			name:    "no source, no constraints",
			options: ServiceOptions{},
		},
		{
			name:    "path source",
			options: ServiceOptions{RedirectsSource: "/internal/redirects"},
		},
		{
			name:    "absolute URL source",
			options: ServiceOptions{RedirectsSource: "https://config.internal/redirects"},
		},
		{
			name:     "interval requires a source",
			options:  ServiceOptions{RedirectsInterval: time.Minute},
			errorMsg: "redirects-interval requires redirects-source",
		},
		{
			name:     "source must be a path or URL",
			options:  ServiceOptions{RedirectsSource: "redirects.json"},
			errorMsg: "redirects-source must be a path or an http(s) URL",
		},
		{
			name:     "URL source needs a host",
			options:  ServiceOptions{RedirectsSource: "https://"},
			errorMsg: "redirects-source must be a path or an http(s) URL",
		},
		{
			name:     "URL source needs a hostname, not just a port",
			options:  ServiceOptions{RedirectsSource: "http://:8080/redirects"},
			errorMsg: "redirects-source must be a path or an http(s) URL",
		},
		{
			name:     "interval below the minimum",
			options:  ServiceOptions{RedirectsSource: "/redirects", RedirectsInterval: time.Second},
			errorMsg: "redirects-interval must be at least",
		},
		{
			name:    "interval at the minimum",
			options: ServiceOptions{RedirectsSource: "/redirects", RedirectsInterval: MinRedirectsInterval},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()
			if tt.errorMsg != "" {
				require.ErrorContains(t, err, tt.errorMsg)
				assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
				return
			}
			require.NoError(t, err)
		})
	}
}

func testDynamicRedirectManager(t testing.TB, config DynamicRedirectConfig) (*DynamicRedirectManager, *fakeResolver) {
	t.Helper()

	if config.StatePath == "" {
		config.StatePath = filepath.Join(t.TempDir(), "dynamic-redirects.state")
	}

	resolver := &fakeResolver{services: map[string]*Service{
		"service1": {name: "service1"},
		"service2": {name: "service2"},
	}}
	dm := NewDynamicRedirectManager(config, resolver)

	// Stop the pollers before the state file's TempDir is removed, so a source
	// does not outlive the test and race the cleanup.
	t.Cleanup(dm.Stop)

	return dm, resolver
}

const testRedirectPayload = `{"hosts": {
	"old.example.com": {"redirect_to": "https://www.tenant.example", "preserve_path": true},
	"www.tenant.example": {"trailing_slash": "strip", "paths": [{"from": "/old", "to": "/new", "status": 302}]}
}}`

func testRedirectsBackend(t testing.TB, payload string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, payload)
	}))
	t.Cleanup(server.Close)

	return server
}

func TestDynamicRedirectManager_DeployedServicePollsAndApplies(t *testing.T) {
	backend := testRedirectsBackend(t, testRedirectPayload)
	dm, resolver := testDynamicRedirectManager(t, DynamicRedirectConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: backend.URL})

	service := resolver.serviceForName("service1")
	require.Eventually(t, func() bool {
		return service.dynamicRedirects.Load() != nil
	}, 5*time.Second, 10*time.Millisecond)

	hosts, rules := service.dynamicRedirects.Load().counts()
	assert.Equal(t, 2, hosts)
	assert.Equal(t, 1, rules)
}

func TestDynamicRedirectManager_KeepsLastGoodOnInvalidPayload(t *testing.T) {
	tracker := installFakeTracker(t)
	dm, resolver := testDynamicRedirectManager(t, DynamicRedirectConfig{})

	// An unreachable source, so the only applied payloads are the ones this
	// test feeds in by hand.
	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/unreachable"})
	require.NoError(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(testRedirectPayload)))

	assert.Equal(t, 1, tracker.redirectPollCount("service1", "applied"))
	hosts, rules := tracker.redirectMapSize("service1")
	assert.Equal(t, 2, hosts)
	assert.Equal(t, 1, rules)

	service := resolver.serviceForName("service1")
	require.NotNil(t, service.dynamicRedirects.Load())

	for _, payload := range []string{
		`{"hosts": {`, // unparseable
		`{}`,          // missing hosts key
		`{"hosts": {"not a hostname": {"paths": []}}}`, // nothing valid survives
	} {
		require.Error(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(payload)), payload)

		hosts, rules := service.dynamicRedirects.Load().counts()
		assert.Equal(t, 2, hosts, payload)
		assert.Equal(t, 1, rules, payload)
	}

	assert.Equal(t, 3, tracker.redirectPollCount("service1", "rejected"))
}

func TestDynamicRedirectManager_ExplicitEmptyPayloadClearsRedirects(t *testing.T) {
	tracker := installFakeTracker(t)
	dm, resolver := testDynamicRedirectManager(t, DynamicRedirectConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/unreachable"})
	require.NoError(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(testRedirectPayload)))

	service := resolver.serviceForName("service1")
	require.NotNil(t, service.dynamicRedirects.Load())

	// The app deleting its last redirect publishes an explicit empty map; that
	// is a clear, not an error.
	require.NoError(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(`{"hosts": {}}`)))

	assert.Nil(t, service.dynamicRedirects.Load())
	hosts, rules := tracker.redirectMapSize("service1")
	assert.Zero(t, hosts)
	assert.Zero(t, rules)
	assert.Equal(t, 2, tracker.redirectPollCount("service1", "applied"))
}

func TestDynamicRedirectManager_SupersededPollerCannotApply(t *testing.T) {
	dm, resolver := testDynamicRedirectManager(t, DynamicRedirectConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/old"})
	oldPoller := dm.sources["service1"]

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/new"})

	// An in-flight poll from the replaced deployment must not install its map.
	require.NoError(t, dm.applyPayload("service1", oldPoller, strings.NewReader(testRedirectPayload)))

	service := resolver.serviceForName("service1")
	assert.Nil(t, service.dynamicRedirects.Load())
}

func TestDynamicRedirectManager_SourceChangeDropsETag(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dynamic-redirects.state")

	dm, _ := testDynamicRedirectManager(t, DynamicRedirectConfig{StatePath: statePath})
	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/old"})
	dm.sources["service1"].SeedETag(`"v1"`)
	require.NoError(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(testRedirectPayload)))
	dm.Stop()

	// Same source: the persisted ETag is seeded so the first poll can 304.
	dm2, _ := testDynamicRedirectManager(t, DynamicRedirectConfig{StatePath: statePath})
	dm2.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/old"})
	assert.Equal(t, `"v1"`, dm2.sources["service1"].ETag())
	dm2.Stop()

	// Different source: the ETag belongs to the old resource and must not be
	// offered to the new one, or a coincidental 304 freezes stale redirects.
	dm3, resolver3 := testDynamicRedirectManager(t, DynamicRedirectConfig{StatePath: statePath})
	dm3.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/new"})
	assert.Empty(t, dm3.sources["service1"].ETag())

	// The persisted map still serves across the source change.
	assert.NotNil(t, resolver3.serviceForName("service1").dynamicRedirects.Load())
}

func TestDynamicRedirectManager_PollFailuresAreCounted(t *testing.T) {
	tracker := installFakeTracker(t)
	dm, _ := testDynamicRedirectManager(t, DynamicRedirectConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/unreachable"})

	require.Eventually(t, func() bool {
		return tracker.redirectPollCount("service1", "error") >= 1
	}, 5*time.Second, 10*time.Millisecond)
}

func TestDynamicRedirectManager_StateSurvivesRestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dynamic-redirects.state")
	backend := testRedirectsBackend(t, testRedirectPayload)

	dm, _ := testDynamicRedirectManager(t, DynamicRedirectConfig{StatePath: statePath})
	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: backend.URL})
	require.NoError(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(testRedirectPayload)))
	dm.Stop()

	// A fresh manager restores state and serves the persisted map on deploy,
	// before any poll happens -- even with the app unreachable.
	dm2, resolver2 := testDynamicRedirectManager(t, DynamicRedirectConfig{StatePath: statePath})
	dm2.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "http://127.0.0.1:1/unreachable"})

	service := resolver2.serviceForName("service1")
	m := service.dynamicRedirects.Load()
	require.NotNil(t, m)

	hosts, rules := m.counts()
	assert.Equal(t, 2, hosts)
	assert.Equal(t, 1, rules)
}

func TestDynamicRedirectManager_ServiceRemovedEvictsRedirects(t *testing.T) {
	backend := testRedirectsBackend(t, testRedirectPayload)
	dm, resolver := testDynamicRedirectManager(t, DynamicRedirectConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: backend.URL})
	require.NoError(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(testRedirectPayload)))

	service := resolver.serviceForName("service1")
	require.NotNil(t, service.dynamicRedirects.Load())

	dm.ServiceRemoved("service1")
	assert.Nil(t, service.dynamicRedirects.Load())
	assert.False(t, dm.HasSources())
}

func TestDynamicRedirectManager_RedeployWithoutSourceEvictsRedirects(t *testing.T) {
	backend := testRedirectsBackend(t, testRedirectPayload)
	dm, resolver := testDynamicRedirectManager(t, DynamicRedirectConfig{})

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: backend.URL})
	require.NoError(t, dm.applyPayload("service1", dm.sources["service1"], strings.NewReader(testRedirectPayload)))

	dm.ServiceDeployed("service1", ServiceOptions{})

	service := resolver.serviceForName("service1")
	assert.Nil(t, service.dynamicRedirects.Load())
}

func TestDynamicRedirectManager_RefreshEndpoint(t *testing.T) {
	backend := testRedirectsBackend(t, testRedirectPayload)
	dm, _ := testDynamicRedirectManager(t, DynamicRedirectConfig{RefreshToken: "refresh-secret"})
	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: backend.URL})

	handler := dm.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	send := func(method, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, redirectsRefreshPath, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	got := send(http.MethodGet, "refresh-secret")
	assert.Equal(t, http.StatusMethodNotAllowed, got.Result().StatusCode)
	assert.Equal(t, http.MethodPost, got.Result().Header.Get("Allow"))

	assert.Equal(t, http.StatusUnauthorized, send(http.MethodPost, "wrong-token").Result().StatusCode)
	assert.Equal(t, http.StatusAccepted, send(http.MethodPost, "refresh-secret").Result().StatusCode)
	// Rate limited within refreshMinInterval
	assert.Equal(t, http.StatusTooManyRequests, send(http.MethodPost, "refresh-secret").Result().StatusCode)

	// Other paths fall through to the wrapped handler
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTeapot, w.Result().StatusCode)
}

func TestDynamicRedirectManager_RefreshEndpointHiddenWithoutToken(t *testing.T) {
	backend := testRedirectsBackend(t, testRedirectPayload)
	dm, _ := testDynamicRedirectManager(t, DynamicRedirectConfig{})
	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: backend.URL})

	handler := dm.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// Every method answers 404 on a disabled endpoint: a 405 for GET would
	// reveal that the route exists.
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		req := httptest.NewRequest(method, redirectsRefreshPath, nil)
		req.Header.Set("Authorization", "Bearer anything")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode, method)
	}
}

func TestRouter_DynamicRedirectsAnswerRequests(t *testing.T) {
	tracker := installFakeTracker(t)
	router := testRouter(t)
	_, target := testBackend(t, "app", http.StatusOK)

	options := defaultServiceOptions
	redirects, err := NewRedirectRules([]string{"/static-old=/static-new"})
	require.NoError(t, err)
	options.Redirects = redirects

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	service := router.serviceForName("service1")
	service.SetDynamicRedirects(compileRedirectMap(map[string]redirectHostConfig{
		"old.example.com":    {RedirectTo: "https://www.tenant.example", PreservePath: true},
		"www.tenant.example": {TrailingSlash: "strip", Paths: []redirectPathRule{{From: "/old", To: "/new", Status: 302}}},
	}))

	tests := []struct {
		name     string
		url      string
		status   int
		location string
		body     string
	}{
		{
			name:     "host-level redirect preserves path and query",
			url:      "http://old.example.com/deep/page?q=1",
			status:   http.StatusMovedPermanently,
			location: "https://www.tenant.example/deep/page?q=1",
		},
		{
			name:     "path rule",
			url:      "http://www.tenant.example/old",
			status:   http.StatusFound,
			location: "http://www.tenant.example/new",
		},
		{
			name:     "trailing slash policy",
			url:      "http://www.tenant.example/docs/",
			status:   http.StatusMovedPermanently,
			location: "http://www.tenant.example/docs",
		},
		{
			name:     "static rules still apply when no dynamic entry matched",
			url:      "http://unrelated.example.com/static-old",
			status:   http.StatusMovedPermanently,
			location: "http://unrelated.example.com/static-new",
		},
		{
			name:   "no rule serves the app",
			url:    "http://www.tenant.example/other",
			status: http.StatusOK,
			body:   "app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.status, w.Result().StatusCode)
			if tt.location != "" {
				assert.Equal(t, tt.location, w.Result().Header.Get("Location"))
			}
			if tt.body != "" {
				assert.Equal(t, tt.body, w.Body.String())
			}
		})
	}

	// Dynamic hits are counted by status; the static rule's redirect is not.
	assert.Equal(t, 2, tracker.redirectHitCount("service1", http.StatusMovedPermanently))
	assert.Equal(t, 1, tracker.redirectHitCount("service1", http.StatusFound))
}

func TestRouter_RedirectRulesNeverShadowInternalPaths(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "app", http.StatusOK)

	// A static catch-all redirect AND a dynamic catch-all: neither may touch
	// ACME challenges or the proxy's own endpoints.
	options := defaultServiceOptions
	redirects, err := NewRedirectRules([]string{"/(.*)=https://elsewhere.example/$1"})
	require.NoError(t, err)
	options.Redirects = redirects

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	router.serviceForName("service1").SetDynamicRedirects(compileRedirectMap(map[string]redirectHostConfig{
		"www.tenant.example": {RedirectTo: "https://elsewhere.example", PreservePath: true},
	}))

	for _, path := range []string{
		"/.well-known/acme-challenge/token123",
		"/.kamal-proxy/anything",
	} {
		t.Run(path, func(t *testing.T) {
			status, body := sendGETRequest(router, "http://www.tenant.example"+path)
			assert.Equal(t, http.StatusOK, status)
			assert.Equal(t, "app", body)
		})
	}
}

func TestService_RedeployWithoutSourceClearsDynamicRedirects(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "app", http.StatusOK)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

	service := router.serviceForName("service1")
	service.SetDynamicRedirects(compileRedirectMap(map[string]redirectHostConfig{
		"old.example.com": {RedirectTo: "https://www.tenant.example"},
	}))
	require.NotNil(t, service.dynamicRedirects.Load())

	// A redeploy without a source clears the map in the service itself, even
	// before the manager's own eviction runs.
	require.NoError(t, service.UpdateOptions(defaultServiceOptions, defaultTargetOptions))
	assert.Nil(t, service.dynamicRedirects.Load())
}

func TestDynamicRedirectManager_EndToEndThroughRouter(t *testing.T) {
	router := testRouter(t)

	// The service's own backend serves the redirect map in path mode.
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirects" {
			fmt.Fprint(w, testRedirectPayload)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

	dm := NewDynamicRedirectManager(DynamicRedirectConfig{
		StatePath: filepath.Join(t.TempDir(), "dynamic-redirects.state"),
	}, router)
	t.Cleanup(dm.Stop)

	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: "/redirects"})

	require.Eventually(t, func() bool {
		status, _ := sendGETRequest(router, "http://old.example.com/page")
		return status == http.StatusMovedPermanently
	}, 5*time.Second, 10*time.Millisecond)
}
