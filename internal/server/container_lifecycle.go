package server

import (
	"context"
	"errors"
)

var (
	// ErrContainerNotFound means the runtime does not know the reference. For a
	// wake that is usually a container the deploy-time preflight saw and
	// something removed since -- `kamal deploy` prunes exited containers, and a
	// sleeping container is exited.
	ErrContainerNotFound = errors.New("container not found")

	// ErrContainerInspectForbidden means the socket answered, but refused to
	// describe the container. Hardened socket proxies commonly allow start and
	// stop while denying inspect, so the deploy preflight warns on this rather
	// than failing -- refusing would lock out the operators doing the right thing.
	ErrContainerInspectForbidden = errors.New("container inspection forbidden")
)

// ContainerLifecycle starts and stops the containers behind a service. It is the
// seam that keeps scale-to-zero independent of how that happens: the shipped
// implementation talks to the Docker socket directly, which is the smallest
// opt-in approach and also grants the proxy root-equivalent access to the host.
// A restricted host-side start/stop service can replace it without the idle
// controller changing at all.
type ContainerLifecycle interface {
	// StartContainer starts the container, returning nil if it is already
	// running. That is what lets a proxy whose state file said "sleeping" for a
	// container that never stopped heal itself on the next request.
	StartContainer(ctx context.Context, ref string) error

	// StopContainer stops the container, returning nil if it is already stopped.
	StopContainer(ctx context.Context, ref string) error

	// ContainerExists reports whether the reference names a container this
	// runtime knows, so a deploy can reject a reference that would only fail
	// hours later at the first idle timeout.
	ContainerExists(ctx context.Context, ref string) error
}
