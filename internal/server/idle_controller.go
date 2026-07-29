package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
)

const (
	// DefaultWakeTimeout bounds the whole hold a request may experience: the
	// stop it may have arrived during, the container start, and the wait for the
	// app to answer a health check.
	DefaultWakeTimeout = 30 * time.Second

	// containerStopTimeout is the budget for putting a service to sleep. No
	// request waits on it, so it does not share the wake timeout. Docker's own
	// stop is SIGTERM then SIGKILL after 10s.
	containerStopTimeout = 30 * time.Second

	// maxWakeBackoff caps the pause between attempts after a wake fails, so a
	// service whose container reference no longer resolves settles at one start
	// attempt per interval instead of one per request.
	maxWakeBackoff = 30 * time.Second

	idleTimerIdlePark = time.Hour
)

var (
	ErrWakeTimeout          = errors.New("timed out waking containers")
	ErrWakeFailed           = errors.New("failed to wake containers")
	ErrNoContainerLifecycle = errors.New("scale-to-zero requires the proxy to run with --docker-socket")
	ErrNotAContainerRef     = errors.New("target does not name a container")
)

// IdleState is where a service's containers are in the scale-to-zero cycle.
type IdleState int

const (
	IdleStateActive IdleState = iota
	IdleStateStopping
	IdleStateSleeping
	IdleStateWaking
)

func (s IdleState) String() string {
	switch s {
	case IdleStateStopping:
		return "stopping"
	case IdleStateSleeping:
		return "sleeping"
	case IdleStateWaking:
		return "waking"
	default:
		return "active"
	}
}

// ParseIdleState reads the name persisted in the state file. The transient
// states fold down to sleeping in both directions: a proxy that died mid
// transition cannot know whether the container moved, and waking from sleeping
// is the safe assumption because starting an already-running container succeeds.
// Anything unrecognised -- including the empty string every state file written
// before this feature existed carries -- restores active.
func ParseIdleState(name string) IdleState {
	switch name {
	case "sleeping", "stopping", "waking":
		return IdleStateSleeping
	default:
		return IdleStateActive
	}
}

// IdleControllerConfig is everything the controller needs from its Service. The
// suspend/resume/persist hooks are supplied rather than reached for, so the
// controller never touches a load balancer, a target, or their locks.
type IdleControllerConfig struct {
	Name        string
	Lifecycle   ContainerLifecycle
	Refs        []string
	SleepAfter  time.Duration
	WakeTimeout time.Duration

	// Suspend takes the targets out of the pool and stops probing them.
	Suspend func()
	// Resume puts them back and waits, within the given budget, for one to answer.
	Resume func(timeout time.Duration) error
	// Persist writes the routing state, so a sleeping service is still sleeping
	// after a proxy restart.
	Persist func()
}

// IdleController stops a service's containers once it has been idle for
// SleepAfter, and starts them again on the next request that needs them.
type IdleController struct {
	name      string
	lifecycle ContainerLifecycle

	suspend func()
	resume  func(timeout time.Duration) error
	persist func()

	lock        sync.Mutex
	state       IdleState
	generation  uint64
	refs        []string
	inflight    int
	lastRequest time.Time
	sleepAfter  time.Duration
	wakeTimeout time.Duration
	lastErr     error
	failures    int
	retryAfter  time.Time
	disabled    bool
	cancel      context.CancelFunc

	// changed is closed on every transition and then replaced. A waiter reads it
	// under the lock, parks on it, and re-reads the state when it wakes, so no
	// decision is ever made from a stale snapshot. Nothing is ever sent on it --
	// the close is the broadcast, the same idiom PauseController uses.
	changed chan struct{}

	signalled chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func NewIdleController(config IdleControllerConfig) *IdleController {
	wakeTimeout := config.WakeTimeout
	if wakeTimeout <= 0 {
		wakeTimeout = DefaultWakeTimeout
	}

	controller := &IdleController{
		name:        config.Name,
		lifecycle:   config.Lifecycle,
		suspend:     config.Suspend,
		resume:      config.Resume,
		persist:     config.Persist,
		refs:        slices.Clone(config.Refs),
		sleepAfter:  config.SleepAfter,
		wakeTimeout: wakeTimeout,
		lastRequest: time.Now(),
		changed:     make(chan struct{}),
		signalled:   make(chan struct{}, 1),
		closed:      make(chan struct{}),
	}

	go controller.run()

	return controller
}

func (c *IdleController) State() IdleState {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.state
}

// RestoreSleeping puts a controller straight into sleeping, for a service whose
// state file said its containers were down. It does not touch the containers --
// they are already stopped, and the next request is what starts them.
func (c *IdleController) RestoreSleeping() {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.state == IdleStateActive {
		c.setStateLocked(IdleStateSleeping)
	}
}

// Close stops the timer goroutine and releases every parked waiter. An in-flight
// container operation is cancelled rather than waited on.
func (c *IdleController) Close() {
	c.closeOnce.Do(func() {
		c.lock.Lock()
		cancel := c.cancel
		c.cancel = nil
		c.lock.Unlock()

		if cancel != nil {
			cancel()
		}
		close(c.closed)
	})
}

// Disable suppresses sleeping without affecting waking, for a service that has
// been paused or stopped. A paused service that let its containers stop would
// turn the resume into a cold start.
func (c *IdleController) Disable() {
	c.lock.Lock()
	c.disabled = true
	c.lock.Unlock()

	c.signal()
}

func (c *IdleController) Enable() {
	c.lock.Lock()
	c.disabled = false
	c.lastRequest = time.Now()
	c.lock.Unlock()

	c.signal()
}

// Reset points the controller at a new set of containers and declares the
// service awake, which is what a redeploy means. Bumping the generation is what
// stops a lifecycle goroutine started before the deploy from writing its outcome
// over the state the deploy just established.
func (c *IdleController) Reset(refs []string) {
	c.lock.Lock()
	c.refs = slices.Clone(refs)
	c.lastRequest = time.Now()
	c.lastErr, c.failures, c.retryAfter = nil, 0, time.Time{}

	cancel := c.cancel
	c.cancel = nil

	if c.state == IdleStateActive {
		// Still bump the generation: a wake or a stop may be in flight even
		// though the state has already settled back to active.
		c.generation++
	} else {
		c.setStateLocked(IdleStateActive)
	}
	c.lock.Unlock()

	if cancel != nil {
		cancel()
	}
	c.signal()
}

// BeginRequest admits a request, waking the service first if it is asleep. It
// blocks the calling request goroutine and never touches the request itself,
// which is why the gate sits above target selection: the request handed on
// afterwards is byte-for-byte the one that arrived, its body still unread.
//
// Every admitted request must be paired with EndRequest.
func (c *IdleController) BeginRequest(ctx context.Context) error {
	// One deadline for the whole call. A per-iteration timer would let a request
	// that arrived while the service was still stopping wait the full timeout for
	// the stop and the full timeout again for the start -- twice the bound the
	// flag documents.
	deadline := time.Now().Add(c.WakeTimeout())

	for {
		changed, err := c.admit()
		if changed == nil {
			return err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrWakeTimeout
		}

		timer := time.NewTimer(remaining)
		select {
		case <-changed:
			timer.Stop()
		case <-timer.C:
			return ErrWakeTimeout
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.closed:
			timer.Stop()
			return ErrWakeFailed
		}
	}
}

// admit either takes a slot for the request, or hands back the channel to wait
// on for the next transition. A nil channel means the caller is finished:
// admitted when err is nil, rejected otherwise.
func (c *IdleController) admit() (<-chan struct{}, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch c.state {
	case IdleStateActive:
		c.inflight++
		c.lastRequest = time.Now()
		return nil, nil

	case IdleStateSleeping:
		if time.Now().Before(c.retryAfter) {
			// A wake failed recently. Fail now rather than hold for the full
			// timeout and issue another doomed start: at request rate that is an
			// unbounded retry storm against the container runtime.
			return nil, c.lastErr
		}
		c.startWakeLocked()
	}

	return c.changed, nil
}

func (c *IdleController) EndRequest() {
	c.lock.Lock()
	if c.inflight > 0 {
		c.inflight--
	}
	// Stamped on the way out as well as in, so an hour-long stream counts as
	// activity for that hour rather than for the instant it started.
	c.lastRequest = time.Now()
	c.lock.Unlock()

	c.signal()
}

// Configure applies a redeploy's settings in place. The controller is created
// once per Service lifetime and reconfigured thereafter, so the request path can
// read s.idleController without a lock.
//
// Changing the container set means the same thing a redeploy does -- the service
// is awake and pointed somewhere new -- so this takes the same generation bump
// Reset does, invalidating any lifecycle goroutine started against the old set.
func (c *IdleController) Configure(sleepAfter, wakeTimeout time.Duration, refs []string) {
	if wakeTimeout <= 0 {
		wakeTimeout = DefaultWakeTimeout
	}

	c.lock.Lock()
	changed := !slices.Equal(c.refs, refs)

	c.sleepAfter = sleepAfter
	c.wakeTimeout = wakeTimeout
	c.refs = slices.Clone(refs)

	var cancel context.CancelFunc
	if changed {
		c.lastRequest = time.Now()
		c.lastErr, c.failures, c.retryAfter = nil, 0, time.Time{}

		cancel = c.cancel
		c.cancel = nil

		if c.state == IdleStateActive {
			c.generation++
		} else {
			c.setStateLocked(IdleStateActive)
		}
	}
	c.lock.Unlock()

	if cancel != nil {
		cancel()
	}
	c.signal()
}

// LastWakeError reports why the most recent wake failed, so a health check can
// stop claiming a service is fine once it can no longer start. Nil once a wake
// has succeeded.
func (c *IdleController) LastWakeError() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.lastErr
}

func (c *IdleController) WakeTimeout() time.Duration {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.wakeTimeout
}

func (c *IdleController) setStateLocked(state IdleState) {
	if c.state == state {
		return
	}

	c.state = state
	c.generation++

	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *IdleController) signal() {
	select {
	case c.signalled <- struct{}{}:
	default:
	}
}

// startWakeLocked is reachable only from the sleeping arm of admit, and flips the
// state while still holding the lock. Concurrent callers therefore serialize on
// that mutex: the first starts the wake, every later one parks on the same
// channel. The coalescing is a consequence of the mutex, not extra machinery.
func (c *IdleController) startWakeLocked() {
	c.setStateLocked(IdleStateWaking)

	generation := c.generation
	refs := slices.Clone(c.refs)
	deadline := time.Now().Add(c.wakeTimeout)
	lifecycle, resume := c.lifecycle, c.resume

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	c.cancel = cancel

	slog.Info("Waking service", "service", c.name, "containers", refs)

	go func() {
		defer cancel()

		var err error
		for _, ref := range refs {
			if startErr := lifecycle.StartContainer(ctx, ref); startErr != nil {
				err = fmt.Errorf("%w: container %s: %w", ErrWakeFailed, ref, startErr)
				break
			}
		}

		if err == nil && resume != nil {
			// Started is not ready. Wait on whatever budget the starts left, not
			// a fresh one.
			if remaining := time.Until(deadline); remaining <= 0 {
				err = ErrWakeTimeout
			} else {
				err = resume(remaining)
			}
		}

		c.finishWake(generation, err)
	}()
}

func (c *IdleController) finishWake(generation uint64, err error) {
	c.lock.Lock()

	// A deploy or a close landed mid-wake and has already decided what the state
	// should be. Do not overwrite it with the outcome of a wake it superseded.
	if c.generation != generation {
		c.lock.Unlock()
		return
	}

	c.cancel = nil
	suspend, persist := c.suspend, c.persist

	if err == nil {
		c.lastErr, c.failures, c.retryAfter = nil, 0, time.Time{}
		c.lastRequest = time.Now()
		c.setStateLocked(IdleStateActive)
	} else {
		c.lastErr = err
		c.failures++
		c.retryAfter = time.Now().Add(wakeBackoff(c.failures))
		c.setStateLocked(IdleStateSleeping)
	}
	c.lock.Unlock()

	if err != nil {
		slog.Error("Failed to wake service", "service", c.name, "error", err)
		// Back out of the pool, so a container that came up but never answered is
		// not probed once a second until somebody notices.
		if suspend != nil {
			suspend()
		}
		return
	}

	slog.Info("Service awake", "service", c.name)
	if persist != nil {
		persist()
	}
}

// wakeBackoff spaces out attempts after a failed wake. Without it a service whose
// container reference no longer resolves costs one start per inbound request,
// forever.
func wakeBackoff(failures int) time.Duration {
	return min(time.Second<<min(failures-1, 5), maxWakeBackoff)
}

func (c *IdleController) trySleep() {
	c.lock.Lock()
	if c.disabled || c.state != IdleStateActive || c.inflight != 0 ||
		c.sleepAfter <= 0 || c.lifecycle == nil || len(c.refs) == 0 ||
		time.Since(c.lastRequest) < c.sleepAfter {
		c.lock.Unlock()
		return
	}

	c.setStateLocked(IdleStateStopping)
	generation := c.generation
	refs := slices.Clone(c.refs)
	lifecycle, suspend, resume, persist := c.lifecycle, c.suspend, c.resume, c.persist
	c.lock.Unlock()

	slog.Info("Sleeping idle service", "service", c.name, "containers", refs)

	// Out of the pool before the containers go down, so nothing probes a container
	// on its way to stopped and nothing is routed to one that already is. Requests
	// arriving now see stopping and are held, so an empty pool is never observable.
	if suspend != nil {
		suspend()
	}

	ctx, cancel := context.WithTimeout(context.Background(), containerStopTimeout)
	defer cancel()

	var stopErr error
	for _, ref := range refs {
		if err := lifecycle.StopContainer(ctx, ref); err != nil {
			slog.Error("Failed to stop idle container", "service", c.name, "container", ref, "error", err)
			stopErr = err
		}
	}

	c.lock.Lock()
	superseded := c.generation != generation
	if !superseded {
		if stopErr == nil {
			c.setStateLocked(IdleStateSleeping)
		} else {
			// Marking the service asleep anyway would turn an unmounted socket or
			// a pruned container into a permanent outage: every later request held
			// for the wake timeout and then failed, for containers that are running
			// perfectly. Roll back and push the next attempt out by a full idle
			// period instead.
			c.lastRequest = time.Now()
			c.setStateLocked(IdleStateActive)
		}
	}
	c.lock.Unlock()

	if superseded {
		return
	}

	if stopErr != nil {
		// Health checks sort out reality: containers that did stop stay out of the
		// pool, ones still running rejoin it.
		if resume != nil {
			if err := resume(containerStopTimeout); err != nil {
				slog.Error("Failed to restore targets after a failed sleep", "service", c.name, "error", err)
			}
		}
		return
	}

	if persist != nil {
		persist()
	}
}

// run is the single idle timer. A service that cannot sleep right now parks for
// an hour and is nudged by signal the moment anything changes, so an active
// service costs one timer rather than one tick per second.
func (c *IdleController) run() {
	for {
		c.lock.Lock()
		wait := c.sleepAfter - time.Since(c.lastRequest)
		eligible := !c.disabled && c.state == IdleStateActive && c.inflight == 0 &&
			c.sleepAfter > 0 && len(c.refs) > 0
		c.lock.Unlock()

		if !eligible {
			wait = idleTimerIdlePark
		}
		wait = max(wait, 0)

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			c.trySleep()
		case <-c.signalled:
			timer.Stop()
		case <-c.closed:
			timer.Stop()
			return
		}
	}
}
