package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"
)

// validateSleep joins the chain in ServiceOptions.Validate.
func (so ServiceOptions) validateSleep() error {
	if so.SleepAfter < 0 || so.WakeTimeout < 0 {
		return fmt.Errorf("%w: sleep-after and wake-timeout cannot be negative", ErrServiceOptionsInvalid)
	}

	if so.SleepAfter > 0 && so.TLSOnDemandURL != "" {
		// An on-demand check asks the backend, at handshake time, whether a host
		// may have a certificate. A sleeping backend cannot answer, and waking one
		// would let any SNI on the internet start a container.
		return fmt.Errorf("%w: sleep-after cannot be used with a TLS on-demand URL", ErrServiceOptionsInvalid)
	}

	if so.SleepAfter <= 0 && len(so.SleepContainers) > 0 {
		return fmt.Errorf("%w: sleep-container requires sleep-after", ErrServiceOptionsInvalid)
	}

	return nil
}

// SetContainerLifecycle installs the runtime that starts and stops this service's
// containers, and builds the idle controller around it. Restored services get
// theirs after the state file is decoded, which is why UnmarshalJSON never
// creates one: at that point the lifecycle is still nil, and a controller built
// there could reach StopContainer on a nil interface.
func (s *Service) SetContainerLifecycle(lifecycle ContainerLifecycle) {
	s.lifecycle = lifecycle
	s.configureIdleController(s.options)

	if s.idleController == nil || s.idleController.State() != IdleStateSleeping {
		return
	}

	// Restore assumed every target healthy. For a sleeping service that is a
	// healthy pool pointing at a stopped container -- and under
	// --recheck-targets-on-restore, a probe against it every second. Put it back
	// the way sleeping left it.
	s.suspendForSleep()
}

// configureIdleController writes s.idleController once per Service lifetime and
// reconfigures in place thereafter, so the request path's unlocked read of it is
// safe by construction.
func (s *Service) configureIdleController(options ServiceOptions) {
	if options.SleepAfter <= 0 {
		if s.idleController != nil {
			s.idleController.Configure(0, 0, nil)
		}
		return
	}

	if s.idleController == nil {
		if s.lifecycle == nil {
			// DeployService refuses sleep-after without a lifecycle, so this is a
			// restored service whose lifecycle arrives later from
			// SetContainerLifecycle.
			return
		}

		s.idleController = NewIdleController(IdleControllerConfig{
			Name:      s.name,
			Lifecycle: s.lifecycle,
			Suspend:   s.suspendForSleep,
			Resume:    s.resumeFromSleep,
			Persist:   s.persistState,
		})

		// Configure first: it treats a changed container set as a redeploy and
		// forces the state back to active, which would undo the restore below. A
		// brand-new controller always sees its refs as changed.
		s.idleController.Configure(options.SleepAfter, options.WakeTimeout, s.containerRefs(options))

		if s.restoredIdleState == IdleStateSleeping {
			s.idleController.RestoreSleeping()
		}

		return
	}

	s.idleController.Configure(options.SleepAfter, options.WakeTimeout, s.containerRefs(options))
}

// containerRefs names the containers behind this service's write targets. Read
// targets are replicas whose lifecycle the proxy does not own, so they are never
// stopped.
func (s *Service) containerRefs(options ServiceOptions) []string {
	if len(options.SleepContainers) > 0 {
		return slices.Clone(options.SleepContainers)
	}

	refs := []string{}
	for _, lb := range []*LoadBalancer{s.active, s.rollout} {
		if lb == nil {
			continue
		}
		for _, target := range lb.WriteTargets() {
			if ref, ok := target.ContainerRef(); ok && !slices.Contains(refs, ref) {
				refs = append(refs, ref)
			}
		}
	}

	return refs
}

func (s *Service) suspendForSleep() {
	s.serviceLock.RLock()
	active, rollout := s.active, s.rollout
	s.serviceLock.RUnlock()

	for _, lb := range []*LoadBalancer{active, rollout} {
		if lb != nil {
			lb.SuspendForSleep()
		}
	}
}

func (s *Service) resumeFromSleep(timeout time.Duration) error {
	s.serviceLock.RLock()
	active, rollout := s.active, s.rollout
	s.serviceLock.RUnlock()

	for _, lb := range []*LoadBalancer{active, rollout} {
		if lb != nil {
			lb.ResumeFromSleep()
		}
	}

	if active == nil {
		return nil
	}

	// Started is not ready: wait for the woken container to actually answer.
	return active.WaitUntilHealthy(timeout)
}

func (s *Service) persistState() {
	if s.statePersister != nil {
		s.statePersister()
	}
}

// handleIdleRequest holds the request until this service's containers are back.
// It reports whether the client has already been answered, and returns the
// function that releases this request's hold on the idle timer.
func (s *Service) handleIdleRequest(w http.ResponseWriter, r *http.Request) (bool, func()) {
	controller := s.idleController
	if controller == nil {
		return false, nil
	}

	// Synthesized inside the proxy -- a TLS on-demand probe -- and must never
	// start a container. validateSleep refuses the combination, so this only
	// guards a state file written before that rule existed.
	if isInternalRequest(r) {
		return false, nil
	}

	// A health check must never wake a service, or an uptime monitor pins it
	// awake forever. It must be answered rather than held, or a load balancer in
	// front evicts a service that is sleeping exactly as intended.
	if s.targetOptions.IsHealthCheckRequest(r) {
		return s.answerIdleHealthCheck(w, r, controller), nil
	}

	if err := controller.BeginRequest(r.Context()); err != nil {
		if errors.Is(err, context.Canceled) {
			// The client hung up mid-wake. Nobody left to answer.
			return true, nil
		}

		// Logged, not rendered: the error carries container references and up to
		// four kilobytes of daemon output, and this response is reachable by
		// anyone who can open a connection.
		slog.Error("Rejecting request: service did not wake",
			"service", s.name, "path", r.URL.Path, "error", err)
		w.Header().Set("Retry-After", "1")
		SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
		return true, nil
	}

	return false, controller.EndRequest
}

// answerIdleHealthCheck answers for a sleeping service without waking it. It
// reports healthy while the sleep is working as intended, and stops the moment a
// wake has actually failed -- otherwise a service that can no longer start
// reports green to its monitoring forever while 503ing every real request.
func (s *Service) answerIdleHealthCheck(w http.ResponseWriter, r *http.Request, controller *IdleController) bool {
	if controller.State() == IdleStateActive {
		return false
	}

	if err := controller.LastWakeError(); err != nil {
		slog.Warn("Reporting unhealthy: last wake failed", "service", s.name, "error", err)
		SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
		return true
	}

	w.WriteHeader(http.StatusOK)
	return true
}

// ContainerRef returns the container this target's address names: its hostname,
// which is a container short id in a Kamal deployment and a container name under
// Compose. It is a best guess -- a Compose service alias resolves over Docker's
// DNS but names no container -- so --sleep-container exists to state it
// explicitly, and the deploy preflight turns a wrong guess into an error on the
// operator's terminal rather than a 503 an hour later.
//
// An address is rejected outright: no container runtime could act on one.
func (t *Target) ContainerRef() (string, bool) {
	host := t.targetURL.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return "", false
	}

	return host, true
}
