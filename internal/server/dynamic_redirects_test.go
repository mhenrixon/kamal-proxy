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
	require.NoError(t, dm.applyPayload("service1", strings.NewReader(testRedirectPayload)))

	assert.Equal(t, 1, tracker.redirectPollCount("service1", "applied"))
	hosts, rules := tracker.redirectMapSize("service1")
	assert.Equal(t, 2, hosts)
	assert.Equal(t, 1, rules)

	service := resolver.serviceForName("service1")
	require.NotNil(t, service.dynamicRedirects.Load())

	for _, payload := range []string{
		`{"hosts": {`,   // unparseable
		`{"hosts": {}}`, // empty must not wipe
		`{}`,            // missing hosts
		`{"hosts": {"not a hostname": {"paths": []}}}`, // nothing valid survives
	} {
		require.Error(t, dm.applyPayload("service1", strings.NewReader(payload)), payload)

		hosts, rules := service.dynamicRedirects.Load().counts()
		assert.Equal(t, 2, hosts, payload)
		assert.Equal(t, 1, rules, payload)
	}

	assert.Equal(t, 4, tracker.redirectPollCount("service1", "rejected"))
}

func TestDynamicRedirectManager_StateSurvivesRestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dynamic-redirects.state")
	backend := testRedirectsBackend(t, testRedirectPayload)

	dm, _ := testDynamicRedirectManager(t, DynamicRedirectConfig{StatePath: statePath})
	dm.ServiceDeployed("service1", ServiceOptions{RedirectsSource: backend.URL})
	require.NoError(t, dm.applyPayload("service1", strings.NewReader(testRedirectPayload)))
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
	require.NoError(t, dm.applyPayload("service1", strings.NewReader(testRedirectPayload)))

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
	require.NoError(t, dm.applyPayload("service1", strings.NewReader(testRedirectPayload)))

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

	send := func(method, token string) int {
		req := httptest.NewRequest(method, redirectsRefreshPath, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result().StatusCode
	}

	assert.Equal(t, http.StatusMethodNotAllowed, send(http.MethodGet, "refresh-secret"))
	assert.Equal(t, http.StatusUnauthorized, send(http.MethodPost, "wrong-token"))
	assert.Equal(t, http.StatusAccepted, send(http.MethodPost, "refresh-secret"))
	// Rate limited within refreshMinInterval
	assert.Equal(t, http.StatusTooManyRequests, send(http.MethodPost, "refresh-secret"))

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

	req := httptest.NewRequest(http.MethodPost, redirectsRefreshPath, nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
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
