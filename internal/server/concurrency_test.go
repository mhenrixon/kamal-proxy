package server

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Saving routing state marshals every service while deploys are replacing their
// load balancers. Both of these run today -- saveStateSnapshot holds only the
// router's read lock, and MarshalJSON read s.active and s.rollout without the
// service lock that UpdateLoadBalancer writes them under.
//
// Only -race fails on the unfixed code; without it the read is simply torn and
// silent, which is why this test asserts nothing beyond "it ran".
func TestService_MarshalJSONIsSafeAgainstConcurrentDeploys(t *testing.T) {
	service, err := NewService("racy", defaultServiceOptions, defaultTargetOptions, nil)
	require.NoError(t, err)

	service.UpdateLoadBalancer(testLoadBalancerWithHandlers(t, func(w http.ResponseWriter, r *http.Request) {}), TargetSlotActive)

	var deploys sync.WaitGroup
	done := make(chan struct{})

	deploys.Add(1)
	go func() {
		defer deploys.Done()
		for {
			select {
			case <-done:
				return
			default:
				lb := testLoadBalancerWithHandlers(t, func(w http.ResponseWriter, r *http.Request) {})
				if replaced := service.UpdateLoadBalancer(lb, TargetSlotActive); replaced != nil {
					replaced.Dispose()
				}
			}
		}
	}()

	for range 200 {
		_, err := json.Marshal(service)
		require.NoError(t, err)
	}

	close(done)
	deploys.Wait()
}

// --recheck-targets-on-restore calls RecheckHealth, which calls BeginHealthChecks
// on a target whose previous health check goroutine may still be running. That
// goroutine reads t.stateConsumer from HealthCheckCompleted while
// BeginHealthChecks writes it, and neither side held the inflight lock.
//
// Honest limitation: unlike the MarshalJSON test above, this one did NOT
// reproduce the race on the unfixed code -- the unsynchronized write and read
// sit either side of the same mutex, so the window is narrow enough that the
// detector did not sample it in a run of this length. It exercises both sides
// concurrently and would catch a coarser regression, but treat it as a smoke
// test, not proof. The fix stands on the code: a field written by one goroutine
// and read by another, now both under the inflight lock.
func TestTarget_BeginHealthChecksIsSafeAgainstAnInFlightCheck(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	t.Cleanup(target.StopHealthChecks)

	consumer := &countingStateConsumer{}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Drive health check completions directly: the real prober's interval is a
	// second, far too slow to collide inside a test.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				target.HealthCheckCompleted(true)
				target.HealthCheckCompleted(false)
			}
		}
	}()

	for range 100 {
		target.BeginHealthChecks(consumer)
	}

	close(done)
	wg.Wait()
}

type countingStateConsumer struct {
	mu      sync.Mutex
	changes int
}

func (c *countingStateConsumer) TargetStateChanged(target *Target) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.changes++
}
