package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every path a request can take through the cache emits exactly one
// client-facing result, so hit + miss + stale + coalesced adds up to the number
// of requests the cache considered. Without that, a hit rate cannot be computed
// from the counter at all.
func TestCacheMetrics_OneClientResultPerRequest(t *testing.T) {
	tests := []struct {
		name     string
		exercise func(t *testing.T, middleware *CacheMiddleware)
		expected map[string]int
	}{
		{
			name: "a cold request is a miss that stores",
			exercise: func(t *testing.T, middleware *CacheMiddleware) {
				getCached(middleware, "http://example.com/p")
			},
			expected: map[string]int{cacheResultMiss: 1, cacheResultStore: 1},
		},
		{
			name: "a warm request is a hit",
			exercise: func(t *testing.T, middleware *CacheMiddleware) {
				getCached(middleware, "http://example.com/p")
				getCached(middleware, "http://example.com/p")
			},
			expected: map[string]int{cacheResultMiss: 1, cacheResultStore: 1, cacheResultHit: 1},
		},
		{
			name: "an ineligible request is not counted at all",
			exercise: func(t *testing.T, middleware *CacheMiddleware) {
				sendCacheRequest(middleware, httptest.NewRequest(http.MethodPost, "http://example.com/p", nil))
			},
			expected: map[string]int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := installFakeTracker(t)
			middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

			tt.exercise(t, middleware)

			for _, result := range []string{cacheResultHit, cacheResultMiss, cacheResultStale, cacheResultCoalesced, cacheResultStore, cacheResultError, cacheResultRevalidated} {
				assert.Equal(t, tt.expected[result], tracker.cacheEventCount(t.Name(), result), "result %q", result)
			}
		})
	}
}

// A background revalidation is not a client request, so counting it as a miss
// made hit + miss + stale + coalesced overshoot the request count and understated
// the hit rate by exactly the traffic stale-while-revalidate is meant to serve.
func TestCacheMetrics_RevalidationIsNotCountedAsAMiss(t *testing.T) {
	tracker := installFakeTracker(t)

	var origin atomic.Int64
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
		w.Write([]byte("body"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/p")
	now = now.Add(30 * time.Second)

	// One stale serve, which starts one refresh behind it.
	require.Equal(t, cacheStatusStale, getCached(middleware, "http://example.com/p").Header().Get("X-Cache"))

	// Wait on the store rather than the revalidated counter: the counter is
	// recorded when the fetch starts, the store when the entry has actually
	// been replaced.
	require.Eventually(t, func() bool {
		return tracker.cacheEventCount(t.Name(), cacheResultStore) == 2
	}, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, tracker.cacheEventCount(t.Name(), cacheResultRevalidated))

	// Once it lands the entry is fresh again, so the rest are plain hits.
	for range 2 {
		require.Equal(t, cacheStatusHit, getCached(middleware, "http://example.com/p").Header().Get("X-Cache"))
	}

	assert.Equal(t, 1, tracker.cacheEventCount(t.Name(), cacheResultMiss), "only the cold request counts as a client miss")
	assert.Equal(t, 1, tracker.cacheEventCount(t.Name(), cacheResultStale))
	assert.Equal(t, 2, tracker.cacheEventCount(t.Name(), cacheResultHit))
	assert.Equal(t, int64(2), origin.Load())

	// Four client requests in, four client-facing results out -- which is what
	// makes hit/(hit+miss+stale+coalesced) a hit rate.
	clientResults := tracker.cacheEventCount(t.Name(), cacheResultHit) +
		tracker.cacheEventCount(t.Name(), cacheResultMiss) +
		tracker.cacheEventCount(t.Name(), cacheResultStale) +
		tracker.cacheEventCount(t.Name(), cacheResultCoalesced)
	assert.Equal(t, 4, clientResults)
}

func TestCacheMetrics_CoalescedRequestsAreCountedApartFromHits(t *testing.T) {
	tracker := installFakeTracker(t)

	arrived := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(arrived) })
		<-release
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte("hello"))
	})

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { getCached(middleware, "http://example.com/p") })
	}

	<-arrived
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, 1, tracker.cacheEventCount(t.Name(), cacheResultMiss))
	assert.Equal(t, 9, tracker.cacheEventCount(t.Name(), cacheResultCoalesced))
	assert.Equal(t, 0, tracker.cacheEventCount(t.Name(), cacheResultHit))
}

// A store that refuses the write still serves the client, and says so.
func TestCacheMetrics_StoreFailureIsCountedAsAnError(t *testing.T) {
	tracker := installFakeTracker(t)

	middleware := WithCacheMiddleware(CacheConfig{
		Service: t.Name(),
		Options: CacheOptions{Enabled: true},
		Store:   failingCacheStore{},
	}, cacheableHandler("hello"))

	response := getCached(middleware, "http://example.com/p")
	assert.Equal(t, "hello", response.Body.String())

	assert.Equal(t, 1, tracker.cacheEventCount(t.Name(), cacheResultMiss))
	assert.Equal(t, 1, tracker.cacheEventCount(t.Name(), cacheResultError))
	assert.Equal(t, 0, tracker.cacheEventCount(t.Name(), cacheResultStore))
}

// failingCacheStore accepts lookups and refuses writes, which is how an
// unreachable shared store behaves from the middleware's point of view.
type failingCacheStore struct{}

func (failingCacheStore) Get(ctx context.Context, key string) (*CacheEntry, bool) { return nil, false }
func (failingCacheStore) Set(ctx context.Context, key string, entry *CacheEntry) error {
	return errors.New("store unavailable")
}
func (failingCacheStore) Purge(ctx context.Context, service, pathPrefix string) (int, error) {
	return 0, errors.New("store unavailable")
}
func (failingCacheStore) Close() error { return nil }
