package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSleepableLoadBalancer builds a SINGLE-target pool on purpose. That is the
// shape scale-to-zero actually targets, and the only shape where the health
// checks stop themselves once the target first goes healthy -- which is what
// makes the resume path subtle.
func testSleepableLoadBalancer(t *testing.T, handler http.HandlerFunc) (*LoadBalancer, *httptest.Server) {
	t.Helper()

	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)

	targets, err := NewTargetList([]string{backend.Listener.Addr().String()}, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(targets, DefaultWriterAffinityTimeout, false)
	t.Cleanup(lb.Dispose)

	require.NoError(t, lb.WaitUntilHealthy(5*time.Second))
	require.Len(t, lb.HealthyTargets(), 1)

	return lb, backend
}

func TestLoadBalancer_SuspendForSleepEmptiesThePoolAndStopsProbing(t *testing.T) {
	var probes atomic.Int64

	lb, _ := testSleepableLoadBalancer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == defaultTargetOptions.HealthCheckConfig.Path {
			probes.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	})

	lb.SuspendForSleep()

	assert.Empty(t, lb.HealthyTargets(), "a deliberately stopped container must not be routed to")

	before := probes.Load()
	time.Sleep(3 * defaultTargetOptions.HealthCheckConfig.Interval)

	assert.Equal(t, before, probes.Load(),
		"a sleeping service must not be dialled once a second for the whole nap")
}

// The defect this whole pair exists for. A single-target pool stops probing at
// first-healthy, so markHealthy has already fired and waitForHealthyContext is
// already cancelled. Without re-arming, WaitUntilHealthy returns nil INSTANTLY
// against a container that has not started -- the wake would report ready and
// forward the held request into a connection refused.
func TestLoadBalancer_ResumeFromSleepRearmsWaitUntilHealthy(t *testing.T) {
	var answering atomic.Bool

	// Answering during setup so the pool reaches healthy the ordinary way, then
	// silenced to stand in for a container that is starting but not yet listening.
	answering.Store(true)

	lb, _ := testSleepableLoadBalancer(t, func(w http.ResponseWriter, r *http.Request) {
		if !answering.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	answering.Store(false)

	lb.SuspendForSleep()
	lb.ResumeFromSleep()

	// Nothing is answering yet, so readiness must NOT be reported.
	err := lb.WaitUntilHealthy(300 * time.Millisecond)
	require.Error(t, err, "readiness was reported for a target that never answered")
	assert.ErrorIs(t, err, ErrorTargetFailedToBecomeHealthy)
	assert.Empty(t, lb.HealthyTargets())

	// Once the backend answers, readiness arrives through the machinery that
	// already exists: probe -> HealthCheckCompleted -> updateHealthyTargets ->
	// markHealthy.
	answering.Store(true)

	require.NoError(t, lb.WaitUntilHealthy(5*time.Second))
	assert.Len(t, lb.HealthyTargets(), 1)
}

// Cancelling the old context instead of replacing it would tell a waiter that
// parked before the resume "healthy" at the exact moment every target was marked
// unverified: WaitUntilHealthy reports any non-deadline cancellation as success.
func TestLoadBalancer_ResumeFromSleepDoesNotReleaseAPreviousWaiter(t *testing.T) {
	var answering atomic.Bool

	answering.Store(true)

	lb, _ := testSleepableLoadBalancer(t, func(w http.ResponseWriter, r *http.Request) {
		if !answering.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	answering.Store(false)

	lb.SuspendForSleep()
	lb.ResumeFromSleep()

	parked := make(chan error, 1)
	go func() { parked <- lb.WaitUntilHealthy(500 * time.Millisecond) }()

	// Give the waiter time to park on the context the resume installed.
	time.Sleep(50 * time.Millisecond)

	// A second resume -- a wake retried after a failure -- must not hand that
	// waiter a success.
	lb.ResumeFromSleep()

	select {
	case err := <-parked:
		t.Fatalf("a resume released a parked waiter instead of an actual health check: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	// It times out rather than ever being released, because the resume replaced
	// the context it parked on along with the markHealthy that would close it.
	// That is the deliberate trade: a waiter spanning a resume gets a timeout it
	// can retry, never a false "healthy" for targets that were just marked
	// unverified. It is also unreachable in the real flow -- the controller
	// serializes wakes behind its generation counter, so each wake calls resume
	// and then waits on the context that same resume installed.
	err := <-parked
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorTargetFailedToBecomeHealthy)
}

// A woken target is held to exactly the standard a freshly deployed one is: it
// re-enters unverified and only joins the pool after a probe succeeds, rather
// than being assumed healthy the way a restored target is.
func TestLoadBalancer_ResumeFromSleepReentersUnverified(t *testing.T) {
	lb, _ := testSleepableLoadBalancer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	lb.SuspendForSleep()
	for _, target := range lb.Targets() {
		assert.Equal(t, TargetStateUnhealthy, target.State(), "suspended targets leave the pool")
	}

	lb.ResumeFromSleep()

	require.NoError(t, lb.WaitUntilHealthy(5*time.Second))
	assert.Len(t, lb.HealthyTargets(), 1)
}

// Sleep and wake are driven from the controller's goroutines while requests are
// still being routed, so the pool mutation has to be safe under -race.
func TestLoadBalancer_SuspendAndResumeAreSafeUnderConcurrentRouting(t *testing.T) {
	lb, _ := testSleepableLoadBalancer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_ = lb.HealthyTargets()
			lb.WaitUntilHealthy(time.Millisecond)
		}
	}()

	for range 20 {
		lb.SuspendForSleep()
		lb.ResumeFromSleep()
	}

	<-done
}
