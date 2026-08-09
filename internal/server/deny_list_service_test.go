package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDeniedService deploys a service behind deny rules and returns a handler
// wired the way the real server wires one.
func testDeniedService(t *testing.T, options ServiceOptions, handler http.HandlerFunc) http.Handler {
	t.Helper()

	router := testRouter(t)
	_, target := testBackendWithHandler(t, handler)

	if options.DenyIPs == nil && options.DenyUserAgents == nil {
		options.DenyIPs = []string{"203.0.113.0/24"}
	}

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	return testRoutedHandler(t, router)
}

func TestDenyListService_EmptyOptionServesEveryone(t *testing.T) {
	options := defaultServiceOptions
	options.DenyIPs = []string{}
	options.DenyUserAgents = []string{}

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDenyListService_RejectsDeniedPeer(t *testing.T) {
	var reachedTarget atomic.Int64

	handler := testDeniedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultHealthCheckPath {
			reachedTarget.Add(1)
		}
		w.Write([]byte("secret"))
	})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, reachedTarget.Load(), "the target must never see a denied request")
}

func TestDenyListService_ServesEveryoneElse(t *testing.T) {
	handler := testDeniedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	resp := testAuthRequest(handler, testRequestFromPeer(testAllowedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", testAuthBody(t, resp))
}

func TestDenyListService_DenyBeatsAllow(t *testing.T) {
	// An address matching both lists is denied: the deny list runs first.
	options := defaultServiceOptions
	options.AllowIPs = []string{"10.0.0.0/8"}
	options.DenyIPs = []string{"10.0.0.5"}

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	resp := testAuthRequest(handler, testRequestFromPeer("10.0.0.5:44321", "http://example.com/"))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp = testAuthRequest(handler, testRequestFromPeer("10.0.0.6:44321", "http://example.com/"))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDenyListService_RejectsBeforeRedirecting(t *testing.T) {
	// Same stance as the allow list: a 403 solicits nothing, so a denied peer
	// is refused rather than redirected to HTTPS first.
	options := defaultServiceOptions
	options.TLSEnabled = true
	options.TLSRedirect = true
	options.Hosts = []string{"example.com"}

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
}

func TestDenyListService_RejectsWithoutSpendingRateLimitBudget(t *testing.T) {
	// A denied client is refused with a 403 every time, never a 429: it must
	// not spend rate-limit budget, and repeated denials must not change the
	// answer.
	options := defaultServiceOptions
	options.RateLimit = 1
	options.RateLimitBurst = 1

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	for range 3 {
		resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestDenyListService_RejectsBeforeChallengingBasicAuth(t *testing.T) {
	options := defaultServiceOptions
	options.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	// A denied network never learns that the service wants credentials.
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

func TestDenyListService_RejectsDeniedUserAgent(t *testing.T) {
	options := defaultServiceOptions
	options.DenyUserAgents = []string{`BadBot/.*`}

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	tests := []struct {
		name           string
		userAgent      string
		expectedStatus int
	}{
		{"matching agent", "BadBot/1.0", http.StatusForbidden},
		{"other agent", "Mozilla/5.0", http.StatusOK},
		{"missing agent", "", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testRequestFromPeer(testAllowedPeer, "http://example.com/")
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			assert.Equal(t, tt.expectedStatus, testAuthRequest(handler, req).StatusCode)
		})
	}
}

func TestDenyListService_ResolvesClientThroughTrustedProxies(t *testing.T) {
	options := defaultServiceOptions
	options.DenyIPs = []string{"203.0.113.0/24"}
	options.TrustedProxies = []string{"10.0.0.0/8"}

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// The peer is a trusted proxy; the denied client is in the forwarded chain.
	req := testRequestFromPeer(testAllowedPeer, "http://example.com/")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	resp := testAuthRequest(handler, req)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Without a trusted peer the same header buys nothing in either direction:
	// a client cannot deny itself into a 403 for someone else, nor be denied on
	// a header it wrote.
	req = testRequestFromPeer(testDeniedPeer, "http://example.com/")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	resp = testAuthRequest(handler, req)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestDenyListService_ExemptsHealthCheckRequests(t *testing.T) {
	handler := testDeniedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {})

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
			req := testRequestFromPeer(testDeniedPeer, "http://example.com"+tt.path)
			req.Method = tt.method

			assert.Equal(t, tt.expectedStatus, testAuthRequest(handler, req).StatusCode)
		})
	}
}

func TestDenyListService_ExemptsInternalRequests(t *testing.T) {
	handler := testDeniedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	req := testRequestFromPeer(testDeniedPeer, "http://example.com/")
	req = req.WithContext(markInternalRequest(req.Context()))

	assert.Equal(t, http.StatusOK, testAuthRequest(handler, req).StatusCode)
}

func TestDenyListService_RejectsRootHealthCheckPath(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	options := defaultServiceOptions
	options.DenyIPs = []string{"203.0.113.0/24"}

	targetOptions := defaultTargetOptions
	targetOptions.HealthCheckConfig.Path = "/"

	err := router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, targetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
	require.ErrorContains(t, err, "health-check-path")
}

func TestDenyListService_RejectionRendersCustomErrorPage(t *testing.T) {
	pagesDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(pagesDir, "403.html"), []byte("<h1>go away</h1>"), 0644))

	options := defaultServiceOptions
	options.ErrorPagePath = pagesDir

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, testAuthBody(t, resp), "go away")
}

func TestDenyListService_TracksDenialsByRuleKind(t *testing.T) {
	fake := installFakeTracker(t)

	options := defaultServiceOptions
	options.DenyIPs = []string{"203.0.113.0/24"}
	options.DenyUserAgents = []string{`BadBot/.*`}

	handler := testDeniedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// IP checks run first, so a request matching both counts as an IP denial.
	req := testRequestFromPeer(testDeniedPeer, "http://example.com/")
	req.Header.Set("User-Agent", "BadBot/1.0")
	testAuthRequest(handler, req)

	req = testRequestFromPeer(testAllowedPeer, "http://example.com/")
	req.Header.Set("User-Agent", "BadBot/1.0")
	testAuthRequest(handler, req)

	assert.Equal(t, 1, fake.denialCount("service1", "ip"))
	assert.Equal(t, 1, fake.denialCount("service1", "user_agent"))
}

func TestDenyListService_StateWrittenBeforeTheOptionStaysOpen(t *testing.T) {
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

	// An upgrade must never start refusing traffic an older proxy served.
	assert.Empty(t, service.options.DenyIPs)
	assert.Empty(t, service.options.DenyUserAgents)
	assert.Nil(t, service.denyRules)
}

func TestDenyListService_UnreadableStoredRulesFailClosed(t *testing.T) {
	state := `
	  {
		"name": "my-app",
		"active_target": "localhost:3000",
		"options": {"deny_ips": ["not-an-ip"]},
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

	// A block that cannot be read back must hold, not silently lapse: the
	// service denies everyone until it is redeployed with readable rules.
	require.NotNil(t, service.denyRules)
	assert.True(t, service.denyRules.denyAll)
}

func TestDenyListService_SurvivesStateRoundTrip(t *testing.T) {
	options := defaultServiceOptions
	options.DenyIPs = []string{"203.0.113.0/24"}
	options.DenyUserAgents = []string{`BadBot/.*`}

	service := testCreateService(t, options, defaultTargetOptions)
	t.Cleanup(service.Dispose)

	encoded, err := json.Marshal(service)
	require.NoError(t, err)

	var restored Service
	require.NoError(t, json.Unmarshal(encoded, &restored))
	t.Cleanup(restored.Dispose)

	require.NotNil(t, restored.denyRules)
	assert.True(t, restored.denyRules.deniesAddr(parseHostAddr(testDeniedPeer)))
	assert.False(t, restored.denyRules.deniesAddr(parseHostAddr(testAllowedPeer)))
	assert.True(t, restored.denyRules.deniesUserAgent("BadBot/1.0"))
	assert.Equal(t, []string{"203.0.113.0/24"}, restored.options.DenyIPs)
	assert.Equal(t, []string{`BadBot/.*`}, restored.options.DenyUserAgents)
}

func TestDenyListService_RedeployWithoutTheFlagRemovesBlock(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	blocked := defaultServiceOptions
	blocked.DenyIPs = []string{"203.0.113.0/24"}

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		blocked, defaultTargetOptions, defaultDeploymentOptions))

	handler := testRoutedHandler(t, router)
	resp := testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

	resp = testAuthRequest(handler, testRequestFromPeer(testDeniedPeer, "http://example.com/"))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
