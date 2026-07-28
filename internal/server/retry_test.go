package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetry_IsReplayableRequest(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		body     string
		expected bool
	}{
		{"GET without a body", http.MethodGet, "", true},
		{"HEAD without a body", http.MethodHead, "", true},
		{"OPTIONS without a body", http.MethodOptions, "", true},
		{"TRACE without a body", http.MethodTrace, "", true},
		{"PUT without a body", http.MethodPut, "", true},
		{"DELETE without a body", http.MethodDelete, "", true},
		{"POST without a body", http.MethodPost, "", false},
		{"PATCH without a body", http.MethodPatch, "", false},
		{"GET with a body", http.MethodGet, "hello", false},
		{"PUT with a body", http.MethodPut, "hello", false},
		{"DELETE with a body", http.MethodDelete, "hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body == "" {
				req = httptest.NewRequest(tt.method, "/", nil)
			} else {
				req = httptest.NewRequest(tt.method, "/", strings.NewReader(tt.body))
			}

			assert.Equal(t, tt.expected, isReplayableRequest(req))
		})
	}
}

func TestRetry_IsReplayableRequestWithUnknownLength(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("chunked"))
	req.ContentLength = -1

	assert.False(t, isReplayableRequest(req))
}

func TestRetry_RetriesPastDrainingTarget(t *testing.T) {
	lb := testRetryingLoadBalancer(t, RetryPolicy{TryDuration: time.Second},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	// A draining target is not removed from the pool, so the round robin still
	// hands requests to it. Every one of them should land on the survivor.
	lb.Targets()[0].updateState(TargetStateDraining)

	for range 4 {
		w := httptest.NewRecorder()
		lb.StartRequest(w, httptest.NewRequest(http.MethodGet, "/", nil))()

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "two", w.Body.String())
	}
}

func TestRetry_RetriesDrainingTargetForNonIdempotentRequests(t *testing.T) {
	// Nothing was forwarded when target selection fails, so even a POST can be
	// placed on another target.
	lb := testRetryingLoadBalancer(t, RetryPolicy{TryDuration: time.Second},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	lb.Targets()[0].updateState(TargetStateDraining)

	w := httptest.NewRecorder()
	lb.StartRequest(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body")))()

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "two", w.Body.String())
}

func TestRetry_RetriesPastUnreachableTarget(t *testing.T) {
	dead, deadURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})
	_, liveURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("live"))
	})

	tl, err := NewTargetList([]string{deadURL, liveURL}, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).
		WithRetryPolicy(RetryPolicy{TryDuration: time.Second, TryInterval: time.Millisecond * 10})
	t.Cleanup(lb.Dispose)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	// The target stays in the pool until its health check notices; until then
	// every request routed to it fails to connect.
	dead.Close()

	for range 4 {
		w := httptest.NewRecorder()
		lb.StartRequest(w, httptest.NewRequest(http.MethodGet, "/", nil))()

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "live", w.Body.String())
	}
}

func TestRetry_DoesNotReplayNonIdempotentRequests(t *testing.T) {
	dead, deadURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})
	dead.Close()

	tl, err := NewTargetList([]string{deadURL}, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).
		WithRetryPolicy(RetryPolicy{TryDuration: time.Second, TryInterval: time.Millisecond * 50})
	t.Cleanup(lb.Dispose)
	lb.MarkAllHealthy()

	w := httptest.NewRecorder()
	started := time.Now()
	lb.StartRequest(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body")))()

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Less(t, time.Since(started), time.Second, "a POST should fail on its first attempt")
}

func TestRetry_RendersTheProxyErrorWhenRetriesAreExhausted(t *testing.T) {
	dead, deadURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})
	dead.Close()

	tl, err := NewTargetList([]string{deadURL}, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).
		WithRetryPolicy(RetryPolicy{TryDuration: time.Millisecond * 100, TryInterval: time.Millisecond * 20})
	t.Cleanup(lb.Dispose)
	lb.MarkAllHealthy()

	w := httptest.NewRecorder()
	started := time.Now()
	lb.StartRequest(w, httptest.NewRequest(http.MethodGet, "/", nil))()
	elapsed := time.Since(started)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.GreaterOrEqual(t, elapsed, time.Millisecond*100, "retries should use the whole try duration")
}

func TestRetry_HoldsUntilATargetBecomesHealthy(t *testing.T) {
	healthy := make(chan struct{})
	targetOptions := defaultTargetOptions
	targetOptions.HealthCheckConfig.Interval = time.Millisecond * 10

	_, targetURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == DefaultHealthCheckPath {
			select {
			case <-healthy:
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		w.Write([]byte("recovered"))
	})

	tl, err := NewTargetList([]string{targetURL}, []string{}, targetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).
		WithRetryPolicy(RetryPolicy{TryDuration: time.Second * 5, TryInterval: time.Millisecond * 10})
	t.Cleanup(lb.Dispose)

	require.Error(t, lb.WaitUntilHealthy(time.Millisecond*50))
	require.Empty(t, lb.HealthyTargets())

	time.AfterFunc(time.Millisecond*50, func() { close(healthy) })

	w := httptest.NewRecorder()
	lb.StartRequest(w, httptest.NewRequest(http.MethodGet, "/", nil))()

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "recovered", w.Body.String())
}

func TestRetry_GivesUpAfterTheTryDuration(t *testing.T) {
	lb := NewLoadBalancer(TargetList{}, DefaultWriterAffinityTimeout, false).
		WithRetryPolicy(RetryPolicy{TryDuration: time.Millisecond * 100, TryInterval: time.Millisecond * 20})
	t.Cleanup(lb.Dispose)

	w := httptest.NewRecorder()
	started := time.Now()
	lb.StartRequest(w, httptest.NewRequest(http.MethodGet, "/", nil))()
	elapsed := time.Since(started)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.GreaterOrEqual(t, elapsed, time.Millisecond*100)
	assert.Less(t, elapsed, time.Second)
}

func TestRetry_StopsWhenTheClientDisconnects(t *testing.T) {
	lb := NewLoadBalancer(TargetList{}, DefaultWriterAffinityTimeout, false).
		WithRetryPolicy(RetryPolicy{TryDuration: time.Minute, TryInterval: time.Millisecond * 10})
	t.Cleanup(lb.Dispose)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	time.AfterFunc(time.Millisecond*50, cancel)

	w := httptest.NewRecorder()
	started := time.Now()
	lb.StartRequest(w, req)()

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Less(t, time.Since(started), time.Second)
}

func TestRetry_DisabledByDefault(t *testing.T) {
	lb := testLoadBalancerWithHandlers(t,
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	lb.Targets()[0].updateState(TargetStateDraining)

	w := httptest.NewRecorder()
	lb.StartRequest(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestRetry_ServiceOptionsValidation(t *testing.T) {
	tests := []struct {
		name          string
		tryDuration   time.Duration
		tryInterval   time.Duration
		expectedError string
	}{
		{name: "both unset"},
		{name: "duration only", tryDuration: time.Second},
		{name: "duration and interval", tryDuration: time.Second, tryInterval: time.Millisecond * 100},
		{
			name:          "interval without duration",
			tryInterval:   time.Millisecond * 100,
			expectedError: "target-try-interval requires target-try-duration",
		},
		{
			name:          "negative duration",
			tryDuration:   -time.Second,
			expectedError: "target-try-duration cannot be negative",
		},
		{
			name:          "negative interval",
			tryDuration:   time.Second,
			tryInterval:   -time.Second,
			expectedError: "target-try-interval cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := defaultServiceOptions
			options.TargetTryDuration = tt.tryDuration
			options.TargetTryInterval = tt.tryInterval

			err := options.Validate()

			if tt.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrServiceOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
			}
		})
	}
}

func TestRetry_StateFilesWithoutRetrySettingsKeepRetriesOff(t *testing.T) {
	_, targetURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	saved := []byte(`{
		"name": "service1",
		"options": {"hosts": ["example.com"], "path_prefixes": ["/"]},
		"target_options": {"health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000}},
		"active_targets": ["` + targetURL + `"],
		"pause_controller": {"state": 0}
	}`)

	var service Service
	require.NoError(t, json.Unmarshal(saved, &service))
	t.Cleanup(service.Dispose)

	assert.Zero(t, service.options.TargetTryDuration)
	assert.Zero(t, service.options.TargetTryInterval)
	assert.False(t, service.active.retryPolicy.enabled())
}

// Helpers

func testRetryingLoadBalancer(t *testing.T, policy RetryPolicy, handlers ...http.HandlerFunc) *LoadBalancer {
	t.Helper()

	targets := []string{}
	for _, h := range handlers {
		targets = append(targets, testTarget(t, h).Address())
	}

	tl, err := NewTargetList(targets, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).WithRetryPolicy(policy)
	t.Cleanup(lb.Dispose)

	return lb
}

func TestRetry_ServiceOptionsReachTheLoadBalancer(t *testing.T) {
	router := testRouter(t)
	_, first := testBackend(t, "first", http.StatusOK)
	_, second := testBackend(t, "second", http.StatusOK)

	serviceOptions := defaultServiceOptions
	serviceOptions.TargetTryDuration = time.Second
	serviceOptions.TargetTryInterval = time.Millisecond * 10

	require.NoError(t, router.DeployService("service1", []string{first, second}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	lb := router.services.Get("service1").ActiveLoadBalancer()
	lb.Targets()[0].updateState(TargetStateDraining)

	for range 4 {
		statusCode, body := sendGETRequest(router, "http://example.com/")

		assert.Equal(t, http.StatusOK, statusCode)
		assert.Equal(t, "second", body)
	}
}
