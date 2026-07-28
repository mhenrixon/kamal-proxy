package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Slack for the pool tests that need real elapsed time. Kept together so a
	// noisy CI box can be accommodated in one place.
	testShortIdleConnTimeout = time.Millisecond * 50
	testIdleExpiryPause      = time.Millisecond * 250
	testIdleReusePause       = time.Millisecond * 50
	testPoolArrivalTimeout   = time.Second * 5
	testPoolSettleWait       = time.Millisecond * 200
)

func TestTargetOptions_PoolSettings(t *testing.T) {
	tests := []struct {
		name     string
		options  TargetOptions
		expected poolSettings
	}{
		{
			name:    "all zero resolves to the proxy defaults",
			options: TargetOptions{},
			expected: poolSettings{
				MaxConns:        0,
				MaxIdleConns:    MaxIdleConnsPerHost,
				IdleConnTimeout: DefaultTargetIdleConnTimeout,
				DialTimeout:     DefaultTargetDialTimeout,
			},
		},
		{
			name: "explicit values are carried through untouched",
			options: TargetOptions{
				MaxConnsPerHost:     5,
				MaxIdleConnsPerHost: 3,
				IdleConnTimeout:     time.Second * 10,
				DialTimeout:         time.Second * 2,
				DisableKeepAlives:   true,
			},
			expected: poolSettings{
				MaxConns:          5,
				MaxIdleConns:      3,
				IdleConnTimeout:   time.Second * 10,
				DialTimeout:       time.Second * 2,
				DisableKeepAlives: true,
			},
		},
		{
			name: "negatives are clamped, as state files are never validated",
			options: TargetOptions{
				MaxConnsPerHost:     -1,
				MaxIdleConnsPerHost: -1,
				IdleConnTimeout:     -time.Second,
				DialTimeout:         -time.Second,
			},
			expected: poolSettings{
				MaxConns:        0,
				MaxIdleConns:    MaxIdleConnsPerHost,
				IdleConnTimeout: DefaultTargetIdleConnTimeout,
				DialTimeout:     DefaultTargetDialTimeout,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.options.poolSettings())
		})
	}
}

func TestNewProxyTransport(t *testing.T) {
	tests := []struct {
		name                    string
		options                 TargetOptions
		responseTimeout         time.Duration
		expectedMaxConns        int
		expectedMaxIdleConns    int
		expectedIdleConnTimeout time.Duration
		expectedKeepAlivesOff   bool
	}{
		{
			name:                    "defaults",
			options:                 TargetOptions{},
			responseTimeout:         DefaultTargetTimeout,
			expectedMaxConns:        0,
			expectedMaxIdleConns:    MaxIdleConnsPerHost,
			expectedIdleConnTimeout: DefaultTargetIdleConnTimeout,
		},
		{
			name: "every knob set",
			options: TargetOptions{
				MaxConnsPerHost:     8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     time.Second * 30,
				DialTimeout:         time.Second * 3,
				DisableKeepAlives:   true,
			},
			responseTimeout:         time.Second * 7,
			expectedMaxConns:        8,
			expectedMaxIdleConns:    4,
			expectedIdleConnTimeout: time.Second * 30,
			expectedKeepAlivesOff:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newProxyTransport(tt.options, tt.responseTimeout)

			assert.Equal(t, tt.expectedMaxConns, transport.MaxConnsPerHost)
			assert.Equal(t, tt.expectedMaxIdleConns, transport.MaxIdleConnsPerHost)
			assert.Equal(t, tt.expectedIdleConnTimeout, transport.IdleConnTimeout)
			assert.Equal(t, tt.expectedKeepAlivesOff, transport.DisableKeepAlives)

			// The response timeout is not a pool setting, and must land on its
			// own field regardless of what the pool knobs are set to.
			assert.Equal(t, tt.responseTimeout, transport.ResponseHeaderTimeout)

			// The dial timeout can only be observed through the dialer we build.
			assert.NotNil(t, transport.DialContext)

			// HTTP_PROXY must never apply to the target leg.
			assert.Nil(t, transport.Proxy)
		})
	}
}

func TestTargetOptions_Validate(t *testing.T) {
	tests := []struct {
		name          string
		options       TargetOptions
		expectedError string
	}{
		{
			name:    "defaults are valid",
			options: defaultTargetOptions,
		},
		{
			name:          "negative max conns",
			options:       TargetOptions{MaxConnsPerHost: -1},
			expectedError: "target-max-conns cannot be negative",
		},
		{
			name:          "negative max idle conns",
			options:       TargetOptions{MaxIdleConnsPerHost: -1},
			expectedError: "target-max-idle-conns cannot be negative",
		},
		{
			name:          "negative idle conn timeout",
			options:       TargetOptions{IdleConnTimeout: -time.Second},
			expectedError: "target-idle-conn-timeout cannot be negative",
		},
		{
			name:          "negative dial timeout",
			options:       TargetOptions{DialTimeout: -time.Second},
			expectedError: "target-dial-timeout cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()

			if tt.expectedError == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, ErrTargetOptionsInvalid)
			require.ErrorContains(t, err, tt.expectedError)
		})
	}
}

func TestTarget_PoolSettingsApplyToPerPathTransports(t *testing.T) {
	targetOptions := defaultTargetOptions
	targetOptions.MaxConnsPerHost = 7
	targetOptions.PathResponseTimeouts = []PathTimeout{{PathPrefix: "/slow", Timeout: 5 * time.Second}}

	target := testTargetWithOptions(t, targetOptions, func(w http.ResponseWriter, r *http.Request) {})

	// Each per-path response timeout needs its own transport, and therefore its
	// own pool. They must not diverge from the default one: the effective
	// ceiling toward this target is 7 x len(transports), not 7.
	require.Len(t, target.transports, 2)
	for _, transport := range target.transports {
		assert.Equal(t, 7, transport.MaxConnsPerHost)
		assert.Equal(t, DefaultTargetIdleConnTimeout, transport.IdleConnTimeout)
	}
}

func TestTarget_DisableKeepAlivesOpensAConnectionPerRequest(t *testing.T) {
	tests := []struct {
		name              string
		disableKeepAlives bool
		expectedAccepts   int64
	}{
		{name: "keep-alives reuse a single connection", disableKeepAlives: false, expectedAccepts: 1},
		{name: "disabled keep-alives dial per request", disableKeepAlives: true, expectedAccepts: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, targetURL := testCountingBackend(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			})

			targetOptions := defaultTargetOptions
			targetOptions.DisableKeepAlives = tt.disableKeepAlives

			target, err := NewTarget(targetURL, targetOptions)
			require.NoError(t, err)

			for range 3 {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				w := httptest.NewRecorder()
				testServeRequestWithTarget(t, target, w, req)
				require.Equal(t, http.StatusOK, w.Result().StatusCode)
			}

			assert.Equal(t, tt.expectedAccepts, listener.accepted.Load())
		})
	}
}

func TestTarget_MaxConnsCapsConcurrency(t *testing.T) {
	// Unblock the backend before anything else unwinds. httptest.Server.Close
	// (registered by testCountingBackend's cleanup) waits for outstanding
	// requests, so an assertion failure that left the handlers parked would
	// hang the whole package rather than report the failure.
	var wg sync.WaitGroup
	release := make(chan struct{})
	defer wg.Wait()
	defer close(release)

	arrived := make(chan struct{}, 16)

	listener, targetURL := testCountingBackend(t, func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		w.Write([]byte("ok"))
	})

	targetOptions := defaultTargetOptions
	targetOptions.MaxConnsPerHost = 2

	target, err := NewTarget(targetURL, targetOptions)
	require.NoError(t, err)

	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			testServeRequestWithTarget(t, target, httptest.NewRecorder(), req)
		}()
	}

	for i := range 2 {
		select {
		case <-arrived:
		case <-time.After(testPoolArrivalTimeout):
			t.Fatalf("only %d of 2 requests reached the target", i)
		}
	}

	// Without the cap all six would be in flight by now; the remaining four must
	// still be queued inside the transport.
	select {
	case <-arrived:
		t.Fatal("a third request reached the target despite MaxConnsPerHost=2")
	case <-time.After(testPoolSettleWait):
	}

	assert.Equal(t, int64(2), listener.accepted.Load())
}

func TestTarget_IdleConnTimeoutClosesIdleConnections(t *testing.T) {
	tests := []struct {
		name            string
		idleConnTimeout time.Duration
		pause           time.Duration
		expectedAccepts int64
	}{
		{
			name:            "an idle connection past the timeout is not reused",
			idleConnTimeout: testShortIdleConnTimeout,
			pause:           testIdleExpiryPause,
			expectedAccepts: 2,
		},
		{
			name:            "an idle connection within the timeout is reused",
			idleConnTimeout: time.Minute,
			pause:           testIdleReusePause,
			expectedAccepts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, targetURL := testCountingBackend(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			})

			targetOptions := defaultTargetOptions
			targetOptions.IdleConnTimeout = tt.idleConnTimeout

			target, err := NewTarget(targetURL, targetOptions)
			require.NoError(t, err)

			sendRequest := func() {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				w := httptest.NewRecorder()
				testServeRequestWithTarget(t, target, w, req)
				require.Equal(t, http.StatusOK, w.Result().StatusCode)
			}

			sendRequest()
			time.Sleep(tt.pause)
			sendRequest()

			assert.Equal(t, tt.expectedAccepts, listener.accepted.Load())
		})
	}
}

func TestTargetPool_StateWrittenBeforePoolSettingsUsesTheDefaults(t *testing.T) {
	state := `
	  {
		"name": "my-app",
		"hosts": ["app.example.com"],
		"active_target": "localhost:3000",
		"rollout_target": "",
		"options": {},
		"target_options": {
		  "health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000},
		  "response_timeout": 30000000000,
		  "forward_headers": true
		},
		"pause_controller": {"state": 0, "stop_message": "", "fail_after": 0},
		"rollout_controller": null
	  }
	`

	var service Service
	require.NoError(t, json.NewDecoder(strings.NewReader(state)).Decode(&service))
	t.Cleanup(service.Dispose)

	// Absent JSON keys decode to zero, and no code path defaults them on load.
	require.Zero(t, service.targetOptions.MaxConnsPerHost)
	require.Zero(t, service.targetOptions.MaxIdleConnsPerHost)
	require.Zero(t, service.targetOptions.IdleConnTimeout)
	require.Zero(t, service.targetOptions.DialTimeout)
	require.False(t, service.targetOptions.DisableKeepAlives)

	// Which is why the resolver, not the cobra flag default, is authoritative:
	// a service restored from a pre-feature state file gets the same pool as a
	// fresh deploy.
	assert.Equal(t, poolSettings{
		MaxConns:        0,
		MaxIdleConns:    MaxIdleConnsPerHost,
		IdleConnTimeout: DefaultTargetIdleConnTimeout,
		DialTimeout:     DefaultTargetDialTimeout,
	}, service.targetOptions.poolSettings())
}

func BenchmarkNewTarget(b *testing.B) {
	options := defaultTargetOptions
	options.PathResponseTimeouts = []PathTimeout{{PathPrefix: "/api", Timeout: 0}}

	b.ReportAllocs()
	for b.Loop() {
		_, err := NewTarget("localhost:3000", options)
		if err != nil {
			b.Fatal(err)
		}
	}
}
