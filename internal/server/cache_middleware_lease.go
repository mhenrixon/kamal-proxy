package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

// How a wait ended, as a metric label.
const (
	// cacheLeaseWaitServed: the holder published and this request was answered
	// from it. One origin fetch the fleet did not make.
	cacheLeaseWaitServed = "served"
	// cacheLeaseWaitReleased: the holder finished with nothing storable, so
	// waiting stopped at once rather than running out the budget.
	cacheLeaseWaitReleased = "released"
	// cacheLeaseWaitExpired: the holder was slower than --cache-lease-wait. This
	// is the label that says the budget is too short for this origin.
	cacheLeaseWaitExpired = "expired"
	// cacheLeaseWaitAbandoned: the client gave up while queued.
	cacheLeaseWaitAbandoned = "abandoned"
)

// The cross-node half of the single flight.
//
// LOAD-BEARING AND INVISIBLE FROM HERE: this is only affordable because
// inflightGroup caps waiters at one per node per key. Polling costs
// nodes x polls, not requests x polls. If the local single flight is ever
// removed or bypassed, the cost model changes by a factor of the request rate
// and this becomes actively harmful.

// acquireLease claims the fetch on the fleet's behalf, or reports that another
// proxy already has it. It returns a zero lease -- which grants -- whenever
// leasing is off, the store cannot arbitrate, or the request asked for its own
// fetch.
func (h *CacheMiddleware) acquireLease(ctx context.Context, key string, allowsStored bool) CacheLease {
	// A request carrying no-cache asked for its own fetch and must never be
	// handed the product of somebody else's, nor make anyone wait on it.
	if h.leaser == nil || !allowsStored {
		return CacheLease{}
	}

	lease := h.leaser.AcquireLease(ctx, key, h.leaseTTL)
	metrics.Tracker.TrackCacheLease(h.config.Service, string(lease.Outcome))

	return lease
}

// releaser returns a function that drops the lease once, on a detached
// goroutine.
//
// Detached because it is called from two places that must not block: when
// forward returns, and the instant the response proves unstorable -- and that
// second hook fires from inside WriteHeader before the client's status line goes
// out, and from inside Write with body bytes in flight. A store round trip there
// would stall the response it is streaming.
func (h *CacheMiddleware) releaser(lease CacheLease) func() {
	if !lease.mine() {
		return func() {}
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			go h.leaser.ReleaseLease(context.WithoutCancel(context.Background()), lease)
		})
	}
}

// awaitLease waits for the proxy holding key to publish, and answers from what
// it published. It reports whether the request was served; false means fetch.
//
// Only a fresh entry ends the wait: a stale one would itself need revalidating,
// which is the fetch the wait exists to avoid.
func (h *CacheMiddleware) awaitLease(w http.ResponseWriter, r *http.Request, key string) bool {
	if h.leaseWait <= 0 {
		return false
	}

	deadline := time.NewTimer(h.leaseWait)
	defer deadline.Stop()

	ticker := time.NewTicker(h.leasePoll)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			entry, held := h.leaser.ProbeLease(r.Context(), key)

			if entry != nil && entry.fresh(h.now()) {
				h.trackLeaseWait(cacheLeaseWaitServed)
				h.replay(w, r, entry, cacheStatusHit, cacheResultCoalesced, h.now())
				return true
			}

			if !held {
				// The holder finished with nothing storable, or died, or the
				// store stopped answering. Either way there is nothing coming.
				h.trackLeaseWait(cacheLeaseWaitReleased)
				return false
			}

		case <-deadline.C:
			h.trackLeaseWait(cacheLeaseWaitExpired)
			return false

		case <-r.Context().Done():
			h.trackLeaseWait(cacheLeaseWaitAbandoned)
			return false
		}
	}
}

func (h *CacheMiddleware) trackLeaseWait(outcome string) {
	metrics.Tracker.TrackCacheLeaseWait(h.config.Service, outcome)
}
