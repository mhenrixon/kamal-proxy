package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// containerPreflightTimeout bounds the deploy-time check. It runs on the RPC
// path, where a hung socket would otherwise hold the operator's terminal open.
const containerPreflightTimeout = 10 * time.Second

// SetContainerLifecycle installs the runtime that starts and stops containers for
// scale-to-zero, and hands it to the services already restored — they were
// decoded before it existed, which is exactly why UnmarshalJSON never builds a
// controller itself.
func (r *Router) SetContainerLifecycle(lifecycle ContainerLifecycle) {
	r.withWriteLock(func() error {
		r.lifecycle = lifecycle

		for _, service := range r.services.All() {
			service.SetContainerLifecycle(lifecycle)
		}
		return nil
	})
}

// validateSleepConfiguration proves, in one round trip at deploy time, that a
// container runtime is reachable and that every reference names a container it
// knows.
//
// Upstream discovered all of that at the first idle timeout instead, marked the
// service asleep regardless, and then failed every request for containers that
// were running perfectly well.
func (r *Router) validateSleepConfiguration(options ServiceOptions, targetURLs []string, targetOptions TargetOptions) error {
	if options.SleepAfter <= 0 {
		return nil
	}

	if r.lifecycle == nil {
		return ErrNoContainerLifecycle
	}

	refs := options.SleepContainers
	if len(refs) == 0 {
		targets, err := NewTargetList(targetURLs, nil, targetOptions)
		if err != nil {
			return err
		}

		for _, target := range targets {
			ref, ok := target.ContainerRef()
			if !ok {
				return fmt.Errorf("%w: target %s is an address, not a container; name the container with --sleep-container",
					ErrNotAContainerRef, target.Address())
			}
			refs = append(refs, ref)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), containerPreflightTimeout)
	defer cancel()

	for _, ref := range refs {
		switch err := r.lifecycle.ContainerExists(ctx, ref); {
		case err == nil:

		case errors.Is(err, ErrContainerNotFound):
			return fmt.Errorf("%w: no container named %q; if the target names a network alias rather than a container, set --sleep-container",
				ErrNotAContainerRef, ref)

		case errors.Is(err, ErrContainerInspectForbidden):
			// A hardened socket proxy commonly allows start and stop while denying
			// inspect. Refusing the deploy for that would lock out exactly the
			// operators doing the right thing, so this is the one preflight failure
			// that is a warning.
			slog.Warn("Cannot verify container for --sleep-after; the socket denies inspect",
				"container", ref, "error", err)

		default:
			return fmt.Errorf("cannot manage container %q for --sleep-after: %w", ref, err)
		}
	}

	return nil
}

// restoreSleepingServices gives every restored service a way to persist, and puts
// the ones that were sleeping back the way sleeping left them.
func (r *Router) restoreSleepingServices(services []*Service) {
	for _, service := range services {
		service.statePersister = r.persistState

		if r.lifecycle != nil {
			service.SetContainerLifecycle(r.lifecycle)
		}
	}
}

// persistState writes the routing state after a sleep or a wake. Errors are
// logged rather than returned: the controller has already moved, and failing to
// record it costs a wrong state on the next boot, not a broken proxy now.
func (r *Router) persistState() {
	if err := r.SaveState(); err != nil {
		slog.Error("Failed to persist idle state", "error", err)
	}
}

// describeServiceState reports the one state an operator most needs to see. A
// paused or stopped service says so -- that is a human decision, and it outranks
// anything traffic-driven -- and otherwise a sleeping or waking service says that
// rather than "running".
func describeServiceState(service *Service) string {
	pauseState := service.pauseController.GetState()
	if pauseState != PauseStateRunning {
		return pauseState.String()
	}

	if service.idleController != nil {
		if idleState := service.idleController.State(); idleState != IdleStateActive {
			return idleState.String()
		}
	}

	return pauseState.String()
}
