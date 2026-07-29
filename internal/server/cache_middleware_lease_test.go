package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCacheFleet builds two middlewares over one shared store, which is a
// two-node fleet in one process. Each has its own inflightGroup, so anything
// they coordinate they coordinate through the lease.
func testCacheFleet(t *testing.T, leases CacheLeaseOptions, handler http.HandlerFunc) (*CacheMiddleware, *CacheMiddleware, *atomic.Int64) {
	t.Helper()

	server := miniredis.RunT(t)

	var origin atomic.Int64
	counted := func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		handler(w, r)
	}

	newNode := func() *CacheMiddleware {
		store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
		require.NoError(t, err)
		t.Cleanup(func() { store.Close() })

		return WithCacheMiddleware(CacheConfig{
			Service: t.Name(),
			Options: CacheOptions{Enabled: true},
			Store:   store,
			Leases:  leases,
		}, http.HandlerFunc(counted))
	}

	return newNode(), newNode(), &origin
}

func publicSlowHandler(delay time.Duration, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte(body))
	}
}

// The headline: a lifetime rolling over costs the application one request for
// the whole fleet, not one per node.
func TestCacheLease_TwoNodesColdMissCostOneUpstreamFetch(t *testing.T) {
	first, second, origin := testCacheFleet(t, CacheLeaseOptions{}, publicSlowHandler(60*time.Millisecond, "hello"))

	bodies := make([]string, 2)
	statuses := make([]string, 2)

	var wg sync.WaitGroup
	for i, node := range []*CacheMiddleware{first, second} {
		wg.Go(func() {
			response := getCached(node, "http://example.com/p")
			bodies[i] = response.Body.String()
			statuses[i] = response.Header().Get("X-Cache")
		})
	}
	wg.Wait()

	assert.Equal(t, int64(1), origin.Load(), "two nodes, one origin fetch")
	assert.Equal(t, []string{"hello", "hello"}, bodies)
	assert.ElementsMatch(t, []string{cacheStatusMiss, cacheStatusHit}, statuses,
		"one node fetched, the other was served from what it published")
}

// The holder's response turns out to be unstorable, so it releases at once
// rather than holding the fleet off for the rest of the TTL.
func TestCacheLease_LoserStopsWaitingWhenTheHolderVanishes(t *testing.T) {
	tracker := installFakeTracker(t)

	first, second, origin := testCacheFleet(t, CacheLeaseOptions{}, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		// Nothing storable comes out of this.
		w.Header().Set("Cache-Control", "private, max-age=60")
		w.Write([]byte("hello"))
	})

	var wg sync.WaitGroup
	started := time.Now()
	for _, node := range []*CacheMiddleware{first, second} {
		wg.Go(func() { getCached(node, "http://example.com/p") })
	}
	wg.Wait()

	assert.Equal(t, int64(2), origin.Load(), "an unstorable response cannot be shared, so both fetch")
	assert.Less(t, time.Since(started), DefaultCacheLeaseWait,
		"the loser should stop the moment the lease clears, not wait out the budget")
	assert.Equal(t, 1, tracker.cacheLeaseWaitCount(t.Name(), cacheLeaseWaitReleased))
}

// A holder slower than the wait budget must not hold a client indefinitely.
func TestCacheLease_LoserForwardsWhenTheBudgetExpires(t *testing.T) {
	tracker := installFakeTracker(t)
	release := make(chan struct{})

	var origin atomic.Int64
	server := miniredis.RunT(t)
	newNode := func() *CacheMiddleware {
		store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
		require.NoError(t, err)
		t.Cleanup(func() { store.Close() })
		return WithCacheMiddleware(CacheConfig{
			Service: t.Name(),
			Options: CacheOptions{Enabled: true},
			Store:   store,
			Leases:  CacheLeaseOptions{Wait: 80 * time.Millisecond},
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if origin.Add(1) == 1 {
				<-release // the holder never publishes in time
			}
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Write([]byte("hello"))
		}))
	}
	first, second := newNode(), newNode()

	var wg sync.WaitGroup
	wg.Go(func() { getCached(first, "http://example.com/p") })
	time.Sleep(20 * time.Millisecond) // let the holder take the lease

	response := getCached(second, "http://example.com/p")
	assert.Equal(t, "hello", response.Body.String(), "the waiter is served by the target, not failed")
	assert.Equal(t, 1, tracker.cacheLeaseWaitCount(t.Name(), cacheLeaseWaitExpired))

	// Let the holder finish before the test ends, or wg.Wait blocks forever.
	close(release)
	wg.Wait()
}

// A stale entry would itself need revalidating, which is the fetch the wait
// exists to avoid -- so only a fresh entry ends the wait.
func TestCacheLease_LoserDoesNotServeAStaleEntry(t *testing.T) {
	server := miniredis.RunT(t)

	var origin atomic.Int64
	newNode := func() *CacheMiddleware {
		store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
		require.NoError(t, err)
		t.Cleanup(func() { store.Close() })
		return WithCacheMiddleware(CacheConfig{
			Service: t.Name(),
			Options: CacheOptions{Enabled: true},
			Store:   store,
			Leases:  CacheLeaseOptions{Wait: 60 * time.Millisecond},
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin.Add(1)
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Write([]byte("fresh"))
		}))
	}
	node := newNode()

	// A stale entry is sitting in the store, and somebody holds the lease.
	store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	key := cacheKey(t.Name(), "", httptest.NewRequest(http.MethodGet, "http://example.com/p", nil), CacheOptions{Enabled: true})
	stale := testStoredEntry(t.Name(), "/p", "stale")
	stale.FreshFor = time.Millisecond
	stale.StaleWhileRevalidate = time.Hour
	require.NoError(t, store.Set(t.Context(), key, stale))
	require.Equal(t, CacheLeaseAcquired, store.(CacheLeaser).AcquireLease(t.Context(), key, time.Minute).Outcome)

	time.Sleep(5 * time.Millisecond) // let the entry go stale

	// The node finds the stale entry first and serves it, revalidating behind --
	// and the revalidation loses the lease, so nothing is fetched.
	response := getCached(node, "http://example.com/p")
	assert.Equal(t, "stale", response.Body.String())
	assert.Equal(t, cacheStatusStale, response.Header().Get("X-Cache"))

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int64(0), origin.Load(), "the revalidation should have deferred to the lease holder")
}

// A request that refuses the stored copy asked for its own fetch. It must never
// be handed the product of somebody else's, and must not make anyone wait.
func TestCacheLease_NoCacheRequestNeverWaitsAndNeverTakesALease(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{name: "no-cache", header: "Cache-Control", value: "no-cache"},
		{name: "max-age=0", header: "Cache-Control", value: "max-age=0"},
		{name: "legacy pragma", header: "Pragma", value: "no-cache"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, second, origin := testCacheFleet(t, CacheLeaseOptions{}, publicSlowHandler(0, "hello"))

			for _, node := range []*CacheMiddleware{first, second} {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
				req.Header.Set(tt.header, tt.value)
				assert.Equal(t, "hello", sendCacheRequest(node, req).Body.String())
			}

			assert.Equal(t, int64(2), origin.Load(), "each reload gets its own fetch")
		})
	}
}

// The free half: nobody is waiting on a background refresh, so a node that loses
// the lease simply does not refresh, and the client already had its answer.
func TestCacheLease_RevalidationLoserSkipsTheRefresh(t *testing.T) {
	server := miniredis.RunT(t)

	var origin atomic.Int64
	newNode := func() *CacheMiddleware {
		store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
		require.NoError(t, err)
		t.Cleanup(func() { store.Close() })
		return WithCacheMiddleware(CacheConfig{
			Service: t.Name(),
			Options: CacheOptions{Enabled: true},
			Store:   store,
			Leases:  CacheLeaseOptions{},
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin.Add(1)
			time.Sleep(40 * time.Millisecond)
			w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
			w.Write([]byte("body"))
		}))
	}
	first, second := newNode(), newNode()

	now := time.Now()
	first.now = func() time.Time { return now }
	second.now = func() time.Time { return now }

	getCached(first, "http://example.com/p")
	require.Equal(t, int64(1), origin.Load())

	now = now.Add(30 * time.Second)

	// Both nodes see a stale entry and both would revalidate; the lease means
	// only one does.
	var wg sync.WaitGroup
	for _, node := range []*CacheMiddleware{first, second} {
		wg.Go(func() {
			response := getCached(node, "http://example.com/p")
			assert.Equal(t, cacheStatusStale, response.Header().Get("X-Cache"), "the client is answered immediately either way")
		})
	}
	wg.Wait()

	time.Sleep(120 * time.Millisecond)
	assert.Equal(t, int64(2), origin.Load(), "one warm-up and one refresh across the fleet")
}

// A refusal fires from inside WriteHeader and mid-Write. Releasing there must
// not put a store round trip in front of bytes the client is already receiving.
func TestCacheLease_ReleasesOnUnstorableWithoutStallingTheResponse(t *testing.T) {
	first, second, _ := testCacheFleet(t, CacheLeaseOptions{}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write(make([]byte, 4096))
	})
	first.config.Options.MaxBodySize = 128
	second.config.Options.MaxBodySize = 128

	response := getCached(first, "http://example.com/p")
	assert.Len(t, response.Body.Bytes(), 4096, "the client still gets the whole body")

	// The lease clears, so the other node is not held off.
	assert.Eventually(t, func() bool {
		return second.config.Store.(CacheLeaser).
			AcquireLease(t.Context(), cacheKey(t.Name(), "", httptest.NewRequest(http.MethodGet, "http://example.com/p", nil), CacheOptions{Enabled: true}), time.Minute).
			Outcome == CacheLeaseAcquired
	}, time.Second, 10*time.Millisecond)
}

// Constraint 2: the default store must not pay for machinery it cannot use.
func TestCacheLease_MemoryStoreAddsNoLeaseBehaviour(t *testing.T) {
	store := testMemoryStore(t)

	_, ok := store.(CacheLeaser)
	assert.False(t, ok, "a store nobody else can see has nothing to arbitrate")

	middleware := WithCacheMiddleware(CacheConfig{
		Service: t.Name(),
		Options: CacheOptions{Enabled: true},
		Store:   store,
		Leases:  CacheLeaseOptions{},
	}, cacheableHandler("hello"))

	assert.Nil(t, middleware.leaser, "no leaser means no round trips and no code paths")
	assert.Equal(t, cacheStatusMiss, getCached(middleware, "http://example.com/p").Header().Get("X-Cache"))
	assert.Equal(t, cacheStatusHit, getCached(middleware, "http://example.com/p").Header().Get("X-Cache"))
}

// Switching leases off must remove every trace of them.
func TestCacheLease_DisabledWritesNoLeaseKeys(t *testing.T) {
	first, second, origin := testCacheFleet(t, CacheLeaseOptions{TTL: -1}, publicSlowHandler(20*time.Millisecond, "hello"))

	assert.Nil(t, first.leaser)

	var wg sync.WaitGroup
	for _, node := range []*CacheMiddleware{first, second} {
		wg.Go(func() { getCached(node, "http://example.com/p") })
	}
	wg.Wait()

	assert.Equal(t, int64(2), origin.Load(), "without leases each node fetches, exactly as before")
}

// Constraint 1, end to end: a store that is down costs duplicate fetches and
// nothing else.
func TestCacheLease_UnreachableStoreBehavesExactlyAsBeforeLeases(t *testing.T) {
	first, second, origin := testCacheFleet(t, CacheLeaseOptions{}, publicSlowHandler(0, "hello"))
	// Take the store away from underneath both nodes.
	first.config.Store.(*redisCacheStore).client.Close()
	second.config.Store.(*redisCacheStore).client.Close()

	for _, node := range []*CacheMiddleware{first, second} {
		response := getCached(node, "http://example.com/p")
		assert.Equal(t, "hello", response.Body.String(), "a dead store must not fail a request")
	}

	assert.Equal(t, int64(2), origin.Load())
}

func TestCacheMetrics_LeaseOutcomesAreRecorded(t *testing.T) {
	tracker := installFakeTracker(t)
	first, second, _ := testCacheFleet(t, CacheLeaseOptions{}, publicSlowHandler(40*time.Millisecond, "hello"))

	var wg sync.WaitGroup
	for _, node := range []*CacheMiddleware{first, second} {
		wg.Go(func() { getCached(node, "http://example.com/p") })
	}
	wg.Wait()

	assert.Equal(t, 1, tracker.cacheLeaseCount(t.Name(), string(CacheLeaseAcquired)))
	assert.Equal(t, 1, tracker.cacheLeaseCount(t.Name(), string(CacheLeaseTaken)))
	assert.Equal(t, 1, tracker.cacheLeaseWaitCount(t.Name(), cacheLeaseWaitServed))

	// The documented invariant survives: a lease-served response is coalesced,
	// already inside the client-facing sum.
	clientResults := tracker.cacheEventCount(t.Name(), cacheResultHit) +
		tracker.cacheEventCount(t.Name(), cacheResultMiss) +
		tracker.cacheEventCount(t.Name(), cacheResultStale) +
		tracker.cacheEventCount(t.Name(), cacheResultCoalesced)
	assert.Equal(t, 2, clientResults)
}
