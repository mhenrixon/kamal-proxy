package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingConsumer struct {
	mu        sync.Mutex
	successes int
	failures  int
	healthy   chan struct{}
	once      sync.Once
}

func newRecordingConsumer() *recordingConsumer {
	return &recordingConsumer{healthy: make(chan struct{})}
}

func (c *recordingConsumer) HealthCheckCompleted(success bool) {
	c.mu.Lock()
	if success {
		c.successes++
	} else {
		c.failures++
	}
	c.mu.Unlock()

	if success {
		c.once.Do(func() { close(c.healthy) })
	}
}

func (c *recordingConsumer) counts() (successes, failures int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.successes, c.failures
}

// A target that is not listening the instant `docker start` returns is the normal
// case, not the exception. Before this, the immediate probe failed and the next
// one came a full interval later -- measured at 1009ms of pure waiting on a
// container whose app was ready almost immediately, which was most of a 1154ms
// cold wake.
func TestHealthCheck_RetriesQuicklyUntilTheFirstSuccess(t *testing.T) {
	var ready atomic.Bool

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			// Stands in for a container whose process exists but is not listening.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	endpoint, err := url.Parse(backend.URL)
	require.NoError(t, err)

	consumer := newRecordingConsumer()

	// A one-second interval, the default. Without the backoff the first success
	// could not arrive before the first tick.
	hc := NewHealthCheck(consumer, endpoint, time.Second, time.Second, "")
	t.Cleanup(hc.Close)

	// Ready well inside one interval, but after the immediate probe has failed.
	time.Sleep(120 * time.Millisecond)
	ready.Store(true)

	start := time.Now()
	select {
	case <-consumer.healthy:
	case <-time.After(900 * time.Millisecond):
		t.Fatal("readiness waited for the full check interval instead of retrying")
	}

	assert.Less(t, time.Since(start), 700*time.Millisecond,
		"a target that became ready must be noticed without waiting out the interval")

	_, failures := consumer.counts()
	assert.Positive(t, failures, "the early probes should have failed and been retried")
}

// Once healthy, the configured interval is what governs -- the fast cadence is
// for catching a boot, not for hammering a running target forever.
func TestHealthCheck_SettlesToTheConfiguredIntervalAfterSuccess(t *testing.T) {
	var probes atomic.Int64

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	endpoint, err := url.Parse(backend.URL)
	require.NoError(t, err)

	consumer := newRecordingConsumer()
	hc := NewHealthCheck(consumer, endpoint, time.Second, time.Second, "")
	t.Cleanup(hc.Close)

	<-consumer.healthy
	settled := probes.Load()

	time.Sleep(400 * time.Millisecond)

	assert.LessOrEqual(t, probes.Load()-settled, int64(1),
		"a healthy target must be probed at its configured interval, not the wake cadence")
}

// A target that never comes up must not be probed in a tight loop for the whole
// wake timeout.
func TestHealthCheck_BackoffIsBoundedByTheConfiguredInterval(t *testing.T) {
	var probes atomic.Int64

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(backend.Close)

	endpoint, err := url.Parse(backend.URL)
	require.NoError(t, err)

	hc := NewHealthCheck(newRecordingConsumer(), endpoint, 200*time.Millisecond, time.Second, "")
	t.Cleanup(hc.Close)

	time.Sleep(time.Second)

	// Doubling from 50ms and capped at the 200ms interval: roughly
	// 50+100+200+200+200 -- far fewer than a 50ms tight loop's 20.
	assert.Less(t, probes.Load(), int64(12),
		"the retry must back off rather than hammer a container that is not coming up")
}
