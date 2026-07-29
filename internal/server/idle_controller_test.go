package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLifecycle counts container operations without touching Docker. Every hook
// is optional; the zero value succeeds instantly.
type fakeLifecycle struct {
	starts atomic.Int64
	stops  atomic.Int64

	startFunc  func(ctx context.Context, ref string) error
	stopFunc   func(ctx context.Context, ref string) error
	existsFunc func(ctx context.Context, ref string) error
}

func (f *fakeLifecycle) StartContainer(ctx context.Context, ref string) error {
	f.starts.Add(1)
	if f.startFunc != nil {
		return f.startFunc(ctx, ref)
	}
	return nil
}

func (f *fakeLifecycle) StopContainer(ctx context.Context, ref string) error {
	f.stops.Add(1)
	if f.stopFunc != nil {
		return f.stopFunc(ctx, ref)
	}
	return nil
}

func (f *fakeLifecycle) ContainerExists(ctx context.Context, ref string) error {
	if f.existsFunc != nil {
		return f.existsFunc(ctx, ref)
	}
	return nil
}

type idleHooks struct {
	mu        sync.Mutex
	suspends  int
	resumes   int
	persists  int
	resumeArg time.Duration

	resumeFunc func(timeout time.Duration) error
}

func (h *idleHooks) counts() (suspends, resumes, persists int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.suspends, h.resumes, h.persists
}

func testIdleController(t *testing.T, lifecycle ContainerLifecycle, sleepAfter time.Duration) (*IdleController, *idleHooks) {
	t.Helper()

	hooks := &idleHooks{}

	controller := NewIdleController(IdleControllerConfig{
		Name:        "test",
		Lifecycle:   lifecycle,
		Refs:        []string{"web-1"},
		SleepAfter:  sleepAfter,
		WakeTimeout: time.Second,
		Suspend: func() {
			hooks.mu.Lock()
			hooks.suspends++
			hooks.mu.Unlock()
		},
		Resume: func(timeout time.Duration) error {
			hooks.mu.Lock()
			hooks.resumes++
			hooks.resumeArg = timeout
			resumeFunc := hooks.resumeFunc
			hooks.mu.Unlock()

			if resumeFunc != nil {
				return resumeFunc(timeout)
			}
			return nil
		},
		Persist: func() {
			hooks.mu.Lock()
			hooks.persists++
			hooks.mu.Unlock()
		},
	})

	t.Cleanup(controller.Close)
	return controller, hooks
}

// waitForState polls until the controller reaches want, so tests never sleep for
// a fixed duration and never race a transition that happens on another goroutine.
func waitForState(t *testing.T, controller *IdleController, want IdleState) {
	t.Helper()

	require.Eventually(t, func() bool {
		return controller.State() == want
	}, 2*time.Second, time.Millisecond, "expected state %s, got %s", want, controller.State())
}

func TestIdleState_NamesRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		expected IdleState
	}{
		{name: "active", expected: IdleStateActive},
		{name: "sleeping", expected: IdleStateSleeping},

		// A proxy that died mid-transition cannot know whether the container
		// moved. Both fold to sleeping, which is safe to wake from: starting an
		// already-running container answers 304.
		{name: "stopping", expected: IdleStateSleeping},
		{name: "waking", expected: IdleStateSleeping},

		// Every state file written before scale-to-zero existed.
		{name: "", expected: IdleStateActive},
		{name: "nonsense", expected: IdleStateActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseIdleState(tt.name))
		})
	}

	assert.Equal(t, "active", IdleStateActive.String())
	assert.Equal(t, "sleeping", IdleStateSleeping.String())
}

func TestIdleController_AdmitsRequestsWhileActive(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	controller, hooks := testIdleController(t, lifecycle, 0)

	require.NoError(t, controller.BeginRequest(context.Background()))
	controller.EndRequest()

	assert.Zero(t, lifecycle.starts.Load(), "an awake service must not start anything")
	assert.Zero(t, lifecycle.stops.Load())

	suspends, resumes, persists := hooks.counts()
	assert.Zero(t, suspends)
	assert.Zero(t, resumes)
	assert.Zero(t, persists)
}

func TestIdleController_SleepsAfterIdlePeriod(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	controller, hooks := testIdleController(t, lifecycle, 10*time.Millisecond)

	waitForState(t, controller, IdleStateSleeping)

	assert.Equal(t, int64(1), lifecycle.stops.Load(), "one stop per container reference")

	suspends, _, persists := hooks.counts()
	assert.Equal(t, 1, suspends, "targets leave the pool before the container goes down")
	assert.Equal(t, 1, persists, "sleeping is a persisted edge")
}

func TestIdleController_DoesNotSleepWithRequestsInFlight(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	controller, _ := testIdleController(t, lifecycle, 10*time.Millisecond)

	// Never released -- this is what a WebSocket or an SSE stream looks like to
	// the controller, and it is the whole guarantee that neither needs
	// special-casing anywhere in the feature.
	require.NoError(t, controller.BeginRequest(context.Background()))

	time.Sleep(80 * time.Millisecond)

	assert.Equal(t, IdleStateActive, controller.State())
	assert.Zero(t, lifecycle.stops.Load(), "a service with an open stream must never sleep")
}

func TestIdleController_WakesOnTheNextRequest(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	controller, hooks := testIdleController(t, lifecycle, 10*time.Millisecond)

	waitForState(t, controller, IdleStateSleeping)

	require.NoError(t, controller.BeginRequest(context.Background()))
	defer controller.EndRequest()

	assert.Equal(t, IdleStateActive, controller.State())
	assert.Equal(t, int64(1), lifecycle.starts.Load())

	hooks.mu.Lock()
	resumeArg := hooks.resumeArg
	hooks.mu.Unlock()
	assert.Positive(t, resumeArg, "resume gets whatever budget the starts left, not a fresh one")
}

func TestIdleController_CoalescesConcurrentWakes(t *testing.T) {
	lifecycle := &fakeLifecycle{
		startFunc: func(ctx context.Context, ref string) error {
			time.Sleep(20 * time.Millisecond)
			return nil
		},
	}
	controller, _ := testIdleController(t, lifecycle, 10*time.Millisecond)

	waitForState(t, controller, IdleStateSleeping)

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	for i := range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = controller.BeginRequest(context.Background())
			if errs[i] == nil {
				controller.EndRequest()
			}
		}()
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "waiter %d", i)
	}
	assert.Equal(t, int64(1), lifecycle.starts.Load(),
		"twenty concurrent requests must coalesce into exactly one container start")
}

func TestIdleController_ClientCancellationReleasesTheWaiterNotTheWake(t *testing.T) {
	lifecycle := &fakeLifecycle{
		startFunc: func(ctx context.Context, ref string) error {
			time.Sleep(50 * time.Millisecond)
			return nil
		},
	}
	controller, _ := testIdleController(t, lifecycle, 10*time.Millisecond)

	waitForState(t, controller, IdleStateSleeping)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := controller.BeginRequest(ctx)
	require.ErrorIs(t, err, context.Canceled, "the client hanging up releases its own waiter")

	// The wake it triggered still completes for everyone else.
	waitForState(t, controller, IdleStateActive)
	assert.Equal(t, int64(1), lifecycle.starts.Load())
}

func TestIdleController_BacksOffAfterAFailedWake(t *testing.T) {
	wakeErr := errors.New("no such container")
	lifecycle := &fakeLifecycle{
		startFunc: func(ctx context.Context, ref string) error { return wakeErr },
	}
	controller, _ := testIdleController(t, lifecycle, 10*time.Millisecond)

	waitForState(t, controller, IdleStateSleeping)

	first := controller.BeginRequest(context.Background())
	require.Error(t, first)

	// Calls 2 and 3 must return the cached error immediately rather than issue
	// another doomed start -- at request rate that is a retry storm.
	for range 2 {
		start := time.Now()
		err := controller.BeginRequest(context.Background())
		require.Error(t, err)
		assert.Less(t, time.Since(start), 100*time.Millisecond, "backoff must fail fast, not hold")
	}

	assert.Equal(t, int64(1), lifecycle.starts.Load(), "exactly one start attempt across three requests")
}

// The exact inverse of upstream #228, which marked the service asleep even when
// the stop failed -- turning an unmounted socket or a pruned container into a
// permanent outage for containers that were running perfectly.
func TestIdleController_StaysAwakeWhenContainersCannotBeStopped(t *testing.T) {
	lifecycle := &fakeLifecycle{
		stopFunc: func(ctx context.Context, ref string) error { return errors.New("permission denied") },
	}
	controller, hooks := testIdleController(t, lifecycle, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		return lifecycle.stops.Load() > 0
	}, 2*time.Second, time.Millisecond)

	waitForState(t, controller, IdleStateActive)

	_, resumes, persists := hooks.counts()
	assert.Positive(t, resumes, "targets go back in the pool so health checks can sort out reality")
	assert.Zero(t, persists, "a rolled-back sleep is not a persisted edge")
}

func TestIdleController_DisableSuppressesSleepOnly(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	controller, _ := testIdleController(t, lifecycle, 10*time.Millisecond)

	controller.Disable()
	time.Sleep(60 * time.Millisecond)

	assert.Equal(t, IdleStateActive, controller.State())
	assert.Zero(t, lifecycle.stops.Load(), "a paused service must not sleep")

	// But a service that is already asleep still wakes on traffic.
	controller.Enable()
	waitForState(t, controller, IdleStateSleeping)
	controller.Disable()

	require.NoError(t, controller.BeginRequest(context.Background()))
	controller.EndRequest()
	assert.Equal(t, IdleStateActive, controller.State())
	assert.Equal(t, int64(1), lifecycle.starts.Load())
}

func TestIdleController_ResetSupersedesAnInFlightWake(t *testing.T) {
	release := make(chan struct{})
	lifecycle := &fakeLifecycle{
		startFunc: func(ctx context.Context, ref string) error {
			<-release
			return nil
		},
	}
	controller, _ := testIdleController(t, lifecycle, 10*time.Millisecond)

	waitForState(t, controller, IdleStateSleeping)

	done := make(chan error, 1)
	go func() { done <- controller.BeginRequest(context.Background()) }()

	waitForState(t, controller, IdleStateWaking)

	// A redeploy lands mid-wake and decides the state itself.
	controller.Reset([]string{"web-2"})
	assert.Equal(t, IdleStateActive, controller.State())

	require.NoError(t, <-done, "the parked waiter proceeds once the deploy makes the service active")

	close(release)

	// The superseded wake's late completion must not move the state back.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, IdleStateActive, controller.State())
}

func TestIdleController_PersistsOnlySleepAndWakeEdges(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	controller, hooks := testIdleController(t, lifecycle, 10*time.Millisecond)

	waitForState(t, controller, IdleStateSleeping)
	require.NoError(t, controller.BeginRequest(context.Background()))
	controller.EndRequest()
	waitForState(t, controller, IdleStateActive)

	_, _, persists := hooks.counts()
	assert.Equal(t, 2, persists, "exactly one persist per edge, two per full cycle")
}
