package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRateLimitedPeer = "203.0.113.5:44321"

// testRateLimitedService deploys a service behind a rate limit and returns a
// handler wired the way the real server wires one.
func testRateLimitedService(t *testing.T, options ServiceOptions, handler http.HandlerFunc) http.Handler {
	t.Helper()

	router := testRouter(t)
	_, target := testBackendWithHandler(t, handler)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	return testRoutedHandler(t, router)
}

func testRateLimitOptions(limit float64, burst int) ServiceOptions {
	options := defaultServiceOptions
	options.RateLimit = limit
	options.RateLimitBurst = burst

	return options
}

func TestRateLimit_ZeroOptionLimitsNothing(t *testing.T) {
	handler := testRateLimitedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	for range 20 {
		resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://example.com/"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func TestRateLimit_Returns429WithRetryAfterOverBudget(t *testing.T) {
	var reachedTarget atomic.Int64

	handler := testRateLimitedService(t, testRateLimitOptions(1, 2), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultHealthCheckPath {
			reachedTarget.Add(1)
		}
		w.Write([]byte("ok"))
	})

	for i := range 2 {
		resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://example.com/"))
		require.Equal(t, http.StatusOK, resp.StatusCode, "request %d is within the burst", i+1)
	}

	resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	assert.EqualValues(t, 2, reachedTarget.Load(), "the limited request must not reach the target")
}

func TestRateLimit_LimitsPerClientNotGlobally(t *testing.T) {
	handler := testRateLimitedService(t, testRateLimitOptions(1, 1), func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	require.Equal(t, http.StatusOK,
		testAuthRequest(handler, testRequestFromPeer("203.0.113.5:44321", "http://example.com/")).StatusCode)
	require.Equal(t, http.StatusTooManyRequests,
		testAuthRequest(handler, testRequestFromPeer("203.0.113.5:44321", "http://example.com/")).StatusCode)

	resp := testAuthRequest(handler, testRequestFromPeer("203.0.113.6:44321", "http://example.com/"))

	assert.Equal(t, http.StatusOK, resp.StatusCode, "one client must not spend another's budget")
}

// A downstream load balancer that gets a 429 on its probe marks this proxy
// down, which turns a rate limit into an outage.
func TestRateLimit_ExemptsHealthCheckRequests(t *testing.T) {
	handler := testRateLimitedService(t, testRateLimitOptions(1, 1), func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	for range 10 {
		resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://example.com"+DefaultHealthCheckPath))
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func TestRateLimit_ExemptRangeBypassesTheLimit(t *testing.T) {
	options := testRateLimitOptions(1, 1)
	options.RateLimitExempt = []string{"10.0.0.0/8"}

	handler := testRateLimitedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	for range 10 {
		resp := testAuthRequest(handler, testRequestFromPeer("10.1.2.3:44321", "http://example.com/"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	require.Equal(t, http.StatusOK,
		testAuthRequest(handler, testRequestFromPeer("203.0.113.9:44321", "http://example.com/")).StatusCode)
	assert.Equal(t, http.StatusTooManyRequests,
		testAuthRequest(handler, testRequestFromPeer("203.0.113.9:44321", "http://example.com/")).StatusCode,
		"a client outside the exempt range is still limited")
	assert.Equal(t, http.StatusOK,
		testAuthRequest(handler, testRequestFromPeer("10.1.2.3:44321", "http://example.com/")).StatusCode)
}

// A 301 never reaches the upstream, so charging it a token would halve the
// effective limit for every browser navigation on a redirecting service.
func TestRateLimit_DoesNotChargeForRedirects(t *testing.T) {
	options := testRateLimitOptions(1, 1)
	options.Hosts = []string{"example.com", "www.example.com"}
	options.CanonicalHost = "example.com"

	handler := testRateLimitedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	for range 5 {
		resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://www.example.com/"))
		require.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	}

	resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusOK, resp.StatusCode, "redirects must not have spent the budget")
}

// Limiting a password-guessing flood is the main thing a rate limit buys a
// --basic-auth service, so the limit has to bind before the challenge.
func TestRateLimit_AppliesBeforeBasicAuthChallenge(t *testing.T) {
	options := testRateLimitOptions(1, 2)

	credential, err := EncodeBasicAuthCredential("user", "secret")
	require.NoError(t, err)
	options.BasicAuth = credential

	handler := testRateLimitedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	for i := range 2 {
		resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://example.com/"))
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "guess %d is within the burst", i+1)
	}

	resp := testAuthRequest(handler, testRequestFromPeer(testRateLimitedPeer, "http://example.com/"))

	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "a guessing flood must be limited")
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

// An address the allow list already refused is not a client with a budget.
func TestRateLimit_DoesNotChargeForDeniedAddresses(t *testing.T) {
	options := testRateLimitOptions(1, 1)
	options.AllowIPs = []string{"10.0.0.0/8"}

	handler := testRateLimitedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	for range 5 {
		resp := testAuthRequest(handler, testRequestFromPeer("203.0.113.9:44321", "http://example.com/"))
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	resp := testAuthRequest(handler, testRequestFromPeer("10.1.2.3:44321", "http://example.com/"))

	assert.Equal(t, http.StatusOK, resp.StatusCode, "denied traffic must not spend an allowed client's budget")
}

// Behind a load balancer every request carries the balancer's peer address, so
// keying on the peer would put the whole internet in one bucket and the first
// burst would lock everyone out.
func TestRateLimit_ResolvesClientsThroughTrustedProxy(t *testing.T) {
	options := testRateLimitOptions(1, 1)
	options.TrustedProxies = []string{"10.0.0.0/8"}

	handler := testRateLimitedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	first := testRequestFromPeer("10.0.0.1:44321", "http://example.com/")
	first.Header.Set("X-Forwarded-For", "203.0.113.5")
	require.Equal(t, http.StatusOK, testAuthRequest(handler, first).StatusCode)

	repeat := testRequestFromPeer("10.0.0.1:44321", "http://example.com/")
	repeat.Header.Set("X-Forwarded-For", "203.0.113.5")
	require.Equal(t, http.StatusTooManyRequests, testAuthRequest(handler, repeat).StatusCode)

	other := testRequestFromPeer("10.0.0.1:44321", "http://example.com/")
	other.Header.Set("X-Forwarded-For", "203.0.113.6")

	assert.Equal(t, http.StatusOK, testAuthRequest(handler, other).StatusCode,
		"each forwarded client needs its own budget")
}

func TestRateLimit_StateWrittenBeforeTheOptionStaysUnlimited(t *testing.T) {
	state := `
	  {
		"name": "my-app",
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

	assert.Zero(t, service.options.RateLimit)
	assert.Nil(t, service.rateLimiter, "an upgrade must not start throttling an existing service")
}

// One unreadable entry must not abort the decode of every other service, and
// must not quietly turn the limit off either.
func TestRateLimit_UnreadableStoredExemptKeepsLimiting(t *testing.T) {
	state := `
	  {
		"name": "my-app",
		"active_target": "localhost:3000",
		"options": {"rate_limit": 1, "rate_limit_burst": 1, "rate_limit_exempt": ["not-an-ip"]},
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

	require.NotNil(t, service.rateLimiter)
	assert.Empty(t, service.rateLimiter.exempt, "an unreadable exempt list must not be honoured")

	req := testRateLimitRequest("10.1.2.3:44321")
	require.True(t, service.rateLimiter.allow(req))
	assert.False(t, service.rateLimiter.allow(req), "the limit itself must stay on")
}

func TestRateLimit_SurvivesStateRoundTrip(t *testing.T) {
	options := testRateLimitOptions(2.5, 7)
	options.RateLimitExempt = []string{"10.0.0.0/8"}

	service := testCreateService(t, options, defaultTargetOptions)
	t.Cleanup(service.Dispose)

	encoded, err := json.Marshal(service)
	require.NoError(t, err)

	var restored Service
	require.NoError(t, json.Unmarshal(encoded, &restored))
	t.Cleanup(restored.Dispose)

	assert.Equal(t, 2.5, restored.options.RateLimit)
	assert.Equal(t, 7, restored.options.RateLimitBurst)
	assert.Equal(t, []string{"10.0.0.0/8"}, restored.options.RateLimitExempt)
	assert.NotNil(t, restored.rateLimiter)
}

func TestRateLimit_Validation(t *testing.T) {
	tests := []struct {
		name          string
		mutate        func(*ServiceOptions)
		expectedError string
	}{
		{
			name:   "limit alone is valid",
			mutate: func(o *ServiceOptions) { o.RateLimit = 10 },
		},
		{
			name:   "limit with burst is valid",
			mutate: func(o *ServiceOptions) { o.RateLimit = 10; o.RateLimitBurst = 20 },
		},
		{
			name:          "negative limit",
			mutate:        func(o *ServiceOptions) { o.RateLimit = -1 },
			expectedError: "rate-limit cannot be negative",
		},
		{
			name:          "burst without a limit",
			mutate:        func(o *ServiceOptions) { o.RateLimitBurst = 5 },
			expectedError: "rate-limit-burst requires rate-limit",
		},
		{
			name:          "negative burst",
			mutate:        func(o *ServiceOptions) { o.RateLimit = 1; o.RateLimitBurst = -1 },
			expectedError: "rate-limit-burst cannot be negative",
		},
		{
			name:          "exempt without a limit",
			mutate:        func(o *ServiceOptions) { o.RateLimitExempt = []string{"10.0.0.0/8"} },
			expectedError: "rate-limit-exempt requires rate-limit",
		},
		{
			name:          "invalid exempt range",
			mutate:        func(o *ServiceOptions) { o.RateLimit = 1; o.RateLimitExempt = []string{"nope"} },
			expectedError: "rate-limit-exempt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := defaultServiceOptions
			tt.mutate(&options)

			err := options.Validate()

			if tt.expectedError == "" {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// Exempting the health check path from the limit is fine; making that path the
// whole site exempts everything.
func TestRateLimit_RejectsRootHealthCheckPath(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	targetOptions := defaultTargetOptions
	targetOptions.HealthCheckConfig.Path = rootPath

	err := router.DeployService("service1", []string{target}, defaultEmptyReaders,
		testRateLimitOptions(1, 1), targetOptions, defaultDeploymentOptions)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
	assert.Contains(t, err.Error(), "health-check-path")
}

// Trusting a header without a declared proxy would let a client pick its own
// bucket, so the combination has to be refused rather than silently ignored.
func TestRateLimit_ClientIPHeaderRequiresTrustedProxy(t *testing.T) {
	options := testRateLimitOptions(1, 1)
	options.ClientIPHeader = "X-Real-IP"

	err := options.Validate()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
	assert.Contains(t, err.Error(), "trusted-proxy")
}

// --trusted-proxy used to require --allow-ip; rate limiting is a second
// legitimate reason to declare the proxies in front.
func TestRateLimit_TrustedProxyIsValidWithoutAllowIP(t *testing.T) {
	options := testRateLimitOptions(1, 1)
	options.TrustedProxies = []string{"10.0.0.0/8"}

	assert.NoError(t, options.Validate())
}

func TestRateLimit_UnlimitedServiceKeepsHeadersUntouched(t *testing.T) {
	handler := testRateLimitedService(t, testRateLimitOptions(100, 100), func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Retry-After"))
}
