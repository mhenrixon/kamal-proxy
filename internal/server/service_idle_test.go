package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceOptions_ValidateSleep(t *testing.T) {
	tests := []struct {
		name          string
		options       ServiceOptions
		expectedError string
	}{
		{
			name:    "sleep disabled by default",
			options: ServiceOptions{Hosts: []string{"app.example.com"}},
		},
		{
			name:    "sleep enabled",
			options: ServiceOptions{Hosts: []string{"app.example.com"}, SleepAfter: time.Minute},
		},
		{
			name:          "negative sleep-after",
			options:       ServiceOptions{Hosts: []string{"app.example.com"}, SleepAfter: -time.Second},
			expectedError: "cannot be negative",
		},
		{
			name:          "negative wake-timeout",
			options:       ServiceOptions{Hosts: []string{"app.example.com"}, SleepAfter: time.Minute, WakeTimeout: -time.Second},
			expectedError: "cannot be negative",
		},
		{
			// An on-demand check asks the backend at handshake time whether a host
			// may have a certificate. A sleeping backend cannot answer, and waking
			// one would let any SNI on the internet start a container.
			name:          "sleep with a TLS on-demand URL",
			options:       ServiceOptions{TLSEnabled: true, TLSOnDemandURL: "/ask", SleepAfter: time.Minute},
			expectedError: "cannot be used with a TLS on-demand URL",
		},
		{
			name:          "sleep-container without sleep-after",
			options:       ServiceOptions{Hosts: []string{"app.example.com"}, SleepContainers: []string{"web-1"}},
			expectedError: "requires sleep-after",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()

			if tt.expectedError == "" {
				assert.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, ErrServiceOptionsInvalid)
			assert.ErrorContains(t, err, tt.expectedError)
		})
	}
}

// The cobra default makes --help honest; Normalize is what gives restored state
// files and direct RPC callers the same value.
func TestServiceOptions_NormalizeDefaultsTheWakeTimeout(t *testing.T) {
	options := ServiceOptions{SleepAfter: time.Minute}
	options.Normalize()
	assert.Equal(t, DefaultWakeTimeout, options.WakeTimeout)

	explicit := ServiceOptions{SleepAfter: time.Minute, WakeTimeout: 5 * time.Second}
	explicit.Normalize()
	assert.Equal(t, 5*time.Second, explicit.WakeTimeout)

	// Nothing is defaulted for a service that does not sleep.
	off := ServiceOptions{}
	off.Normalize()
	assert.Zero(t, off.WakeTimeout)
}

func testSleepingService(t *testing.T, lifecycle ContainerLifecycle, handler http.HandlerFunc) *Service {
	t.Helper()

	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)

	options := defaultServiceOptions
	options.Hosts = []string{"app.example.com"}
	options.SleepAfter = time.Hour // long: these tests drive the controller directly
	// A httptest backend listens on 127.0.0.1, which ContainerRef rightly refuses
	// as an address rather than a container -- so name it explicitly, which is
	// exactly what --sleep-container exists for.
	options.SleepContainers = []string{"web-1"}

	service, err := NewService("sleepy", options, defaultTargetOptions, nil)
	require.NoError(t, err)
	t.Cleanup(service.Dispose)

	targets, err := NewTargetList([]string{backend.Listener.Addr().String()}, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(targets, DefaultWriterAffinityTimeout, false)
	t.Cleanup(lb.Dispose)
	require.NoError(t, lb.WaitUntilHealthy(5*time.Second))

	service.SetContainerLifecycle(lifecycle)
	service.UpdateLoadBalancer(lb, TargetSlotActive)

	require.NotNil(t, service.idleController, "a service with --sleep-after gets a controller")
	require.NotEmpty(t, service.containerRefs(service.options),
		"refs must be derived once the load balancer is installed, or a wake starts nothing")

	return service
}

func sendServiceRequest(service *Service, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, req)
	return recorder
}

// A sleeping service wakes on a real request and forwards it, body intact.
func TestService_SleepingServiceWakesOnARequest(t *testing.T) {
	lifecycle := &fakeLifecycle{}

	service := testSleepingService(t, lifecycle, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	service.idleController.RestoreSleeping()
	require.Equal(t, IdleStateSleeping, service.idleController.State())

	recorder := sendServiceRequest(service, "/")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, int64(1), lifecycle.starts.Load(), "the request woke the containers")
	assert.Equal(t, IdleStateActive, service.idleController.State())
}

// An uptime monitor polling /up would otherwise pin a service awake forever.
func TestService_HealthCheckNeitherWakesNorIsHeld(t *testing.T) {
	lifecycle := &fakeLifecycle{}

	service := testSleepingService(t, lifecycle, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	service.idleController.RestoreSleeping()

	recorder := sendServiceRequest(service, defaultTargetOptions.HealthCheckConfig.Path)

	assert.Equal(t, http.StatusOK, recorder.Code, "a sleeping service is healthy, not down")
	assert.Zero(t, lifecycle.starts.Load(), "monitoring must never start a container")
	assert.Equal(t, IdleStateSleeping, service.idleController.State())
}

// The other half: once a wake has actually failed, monitoring must stop being
// told everything is fine while every real request 503s.
func TestService_HealthCheckReportsUnhealthyAfterAFailedWake(t *testing.T) {
	lifecycle := &fakeLifecycle{
		startFunc: func(ctx context.Context, ref string) error { return errors.New("no such container") },
	}

	service := testSleepingService(t, lifecycle, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	service.idleController.RestoreSleeping()

	// A real request tries to wake and fails.
	failed := sendServiceRequest(service, "/")
	require.Equal(t, http.StatusServiceUnavailable, failed.Code)

	health := sendServiceRequest(service, defaultTargetOptions.HealthCheckConfig.Path)
	assert.Equal(t, http.StatusServiceUnavailable, health.Code,
		"a service that can no longer start must not report green to its monitoring")
}

// The wake error carries container references and up to 4 KB of daemon output,
// and this response is reachable by anyone who can open a connection.
func TestService_WakeFailureDoesNotLeakDaemonDetailToTheClient(t *testing.T) {
	lifecycle := &fakeLifecycle{
		startFunc: func(ctx context.Context, ref string) error {
			return errors.New("secret-container-name: permission denied on /var/run/docker.sock")
		},
	}

	service := testSleepingService(t, lifecycle, func(w http.ResponseWriter, r *http.Request) {})
	service.idleController.RestoreSleeping()

	recorder := sendServiceRequest(service, "/")

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), "secret-container-name")
	assert.NotContains(t, recorder.Body.String(), "docker.sock")
	assert.Equal(t, "1", recorder.Header().Get("Retry-After"))
}

// The proxy's own TLS on-demand probe is synthesized internally and must never
// spend a container start.
func TestService_InternalRequestsDoNotWake(t *testing.T) {
	lifecycle := &fakeLifecycle{}

	service := testSleepingService(t, lifecycle, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	service.idleController.RestoreSleeping()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req = req.WithContext(markInternalRequest(req.Context()))
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, req)

	assert.Zero(t, lifecycle.starts.Load(), "an internal probe must never start a container")
}

func TestService_ContainerRefsPreferTheExplicitOverride(t *testing.T) {
	options := defaultServiceOptions
	options.Hosts = []string{"app.example.com"}
	options.SleepAfter = time.Hour
	options.SleepContainers = []string{"explicit-1", "explicit-2"}

	service, err := NewService("refs", options, defaultTargetOptions, nil)
	require.NoError(t, err)
	t.Cleanup(service.Dispose)

	assert.Equal(t, []string{"explicit-1", "explicit-2"}, service.containerRefs(options),
		"--sleep-container replaces inference entirely")
}

func TestTarget_ContainerRef(t *testing.T) {
	tests := []struct {
		address  string
		expected string
		ok       bool
	}{
		{address: "web-1", expected: "web-1", ok: true},
		{address: "web-1:3000", expected: "web-1", ok: true},
		{address: "3f2a1b9c4d5e:3000", expected: "3f2a1b9c4d5e", ok: true},

		// An address names no container, and no runtime could ever act on it.
		{address: "10.0.0.5:3000", ok: false},
		{address: "127.0.0.1:80", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			target, err := NewTarget(tt.address, defaultTargetOptions)
			require.NoError(t, err)

			ref, ok := target.ContainerRef()
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, ref)
			}
		})
	}
}

// Old state files predate the field and must restore with the feature off.
func TestService_IdleStateRoundTrip(t *testing.T) {
	assert.Equal(t, IdleStateActive, ParseIdleState(""))

	service := testSleepingService(t, &fakeLifecycle{}, func(w http.ResponseWriter, r *http.Request) {})
	service.idleController.RestoreSleeping()

	encoded, err := service.MarshalJSON()
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"idle_state":"sleeping"`)

	var restored Service
	require.NoError(t, restored.UnmarshalJSON(encoded))
	t.Cleanup(restored.Dispose)

	assert.Equal(t, time.Hour, restored.options.SleepAfter)
	assert.Equal(t, IdleStateSleeping, restored.restoredIdleState)
	assert.Nil(t, restored.idleController,
		"UnmarshalJSON must not build a controller: the lifecycle is still nil here")
}

// A state file written before this feature existed restores with sleep off and
// re-marshals byte-identically, because every new key is omitempty.
func TestService_StateFileWithoutIdleStateRestoresAwake(t *testing.T) {
	targetOptions, err := json.Marshal(defaultTargetOptions)
	require.NoError(t, err)

	// No idle_state key, and no sleep_after in options -- exactly what every
	// state file written before this feature looks like.
	legacy := fmt.Sprintf(
		`{"name":"old","options":{"hosts":["app.example.com"]},"target_options":%s,"active_targets":["web-1:3000"]}`,
		targetOptions)

	var restored Service
	require.NoError(t, restored.UnmarshalJSON([]byte(legacy)))
	t.Cleanup(restored.Dispose)

	assert.Zero(t, restored.options.SleepAfter)
	assert.Equal(t, IdleStateActive, restored.restoredIdleState)
	assert.Nil(t, restored.idleController)
}
