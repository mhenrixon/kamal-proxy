package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStatsStore(t *testing.T, maxBytes int64) CacheStore {
	t.Helper()

	store, err := NewCacheStore(CacheStoreConfig{URL: CacheStoreMemory, MemorySize: maxBytes})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

func testStats(t *testing.T, store CacheStore, options CacheStatsOptions) CacheStats {
	t.Helper()

	reporter, ok := store.(CacheReporter)
	require.True(t, ok, "the store should be able to describe itself")

	stats, err := reporter.Stats(t.Context(), options)
	require.NoError(t, err)

	return stats
}

func TestMemoryStats_ReportsWhatItHolds(t *testing.T) {
	// size() counts the service and path too, so entries only weigh the same
	// when they are the same shape.
	shop := testStoredEntry("shop", "/products", "hello")
	blog := testStoredEntry("blog", "/posts", "hello")
	store := testStatsStore(t, shop.size()*10)

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", shop))
	require.NoError(t, store.Set(t.Context(), "kp:c:blog:one", blog))

	stats := testStats(t, store, CacheStatsOptions{})

	assert.Equal(t, CacheStoreMemory, stats.Store)
	assert.False(t, stats.Shared, "nobody else can see an in-process cache")
	assert.Nil(t, stats.Server, "there is no server to describe")

	assert.True(t, stats.Local.Counted, "the in-process store always knows what it holds")
	assert.Equal(t, int64(2), stats.Local.Entries)
	assert.Equal(t, shop.size()+blog.size(), stats.Local.Bytes)
	assert.Equal(t, shop.size()*10, stats.Local.MaxBytes)
	assert.Empty(t, stats.Local.Services, "a per-service breakdown is only produced when asked for")
}

// The number that answers "is --cache-memory-size big enough": an entry pushed
// out with lifetime still on it was fetched and never fully used. A full cache
// evicting only stale entries is a cache doing its job, which is why a single
// eviction count answers nothing.
func TestMemoryStats_SplitsEvictionsByRemainingLifetime(t *testing.T) {
	entry := testStoredEntry("shop", "/products", "hello")
	store := testStatsStore(t, entry.size()*2)

	fresh := func(key string) {
		require.NoError(t, store.Set(t.Context(), key, testStoredEntry("shop", "/products", "hello")))
	}

	fresh("kp:c:shop:one")
	fresh("kp:c:shop:two")
	fresh("kp:c:shop:three") // displaces one

	stats := testStats(t, store, CacheStatsOptions{})
	assert.Equal(t, int64(1), stats.Local.EvictedFresh)
	assert.Equal(t, int64(0), stats.Local.EvictedStale)

	// An entry evicted past its usefulness says nothing about the budget.
	store = testStatsStore(t, entry.size()*2)
	expiring := testStoredEntry("shop", "/products", "hello")
	expiring.FreshFor = time.Millisecond
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", expiring))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/products", "hello")))

	time.Sleep(5 * time.Millisecond)
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:three", testStoredEntry("shop", "/products", "hello")))

	stats = testStats(t, store, CacheStatsOptions{})
	assert.Equal(t, int64(1), stats.Local.EvictedStale)
	assert.Equal(t, int64(0), stats.Local.EvictedFresh)
}

// Only the budget loop counts. An entry dropped because it expired on lookup, or
// replaced by a newer copy of itself, or purged, is not budget pressure and must
// not read as it.
func TestMemoryStats_CountsOnlyBudgetEvictions(t *testing.T) {
	entry := testStoredEntry("shop", "/products", "hello")
	store := testStatsStore(t, entry.size()*10)

	// Replaced by a newer copy of itself.
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "world")))

	// Dropped because it expired on lookup.
	expiring := testStoredEntry("shop", "/products", "hello")
	expiring.FreshFor = time.Millisecond
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", expiring))
	time.Sleep(5 * time.Millisecond)
	_, found := store.Get(t.Context(), "kp:c:shop:two")
	require.False(t, found)

	// Purged.
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:three", testStoredEntry("shop", "/products", "hello")))
	_, err := store.Purge(t.Context(), "shop", "/products")
	require.NoError(t, err)

	stats := testStats(t, store, CacheStatsOptions{})
	assert.Equal(t, int64(0), stats.Local.EvictedFresh)
	assert.Equal(t, int64(0), stats.Local.EvictedStale)
}

// A response too big for the whole budget is a misconfiguration, not pressure.
func TestMemoryStats_CountsOversizedRefusals(t *testing.T) {
	small := testStoredEntry("shop", "/products", "hello")
	store := testStatsStore(t, small.size()+10)

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:small", small))

	oversized := testStoredEntry("shop", "/big", "")
	oversized.Body = make([]byte, small.size()*4)
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:big", oversized))

	stats := testStats(t, store, CacheStatsOptions{})
	assert.Equal(t, int64(1), stats.Local.Oversized)
	assert.Equal(t, int64(0), stats.Local.EvictedFresh, "refusing an oversized entry evicts nothing")
	assert.Equal(t, int64(1), stats.Local.Entries, "and leaves what already fit")
}

func TestMemoryStats_BreaksDownByServiceOnlyWhenCounted(t *testing.T) {
	entry := testStoredEntry("shop", "/products", "hello")
	store := testStatsStore(t, entry.size()*20)

	// Same shape, so the per-service byte total is a clean multiple.
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/products", "world")))
	require.NoError(t, store.Set(t.Context(), "kp:c:blog:one", testStoredEntry("blog", "/posts", "hello")))

	assert.Empty(t, testStats(t, store, CacheStatsOptions{}).Local.Services)

	counted := testStats(t, store, CacheStatsOptions{Count: true}).Local.Services
	require.Len(t, counted, 2)

	byService := map[string]CacheServiceStats{}
	for _, service := range counted {
		byService[service.Service] = service
	}

	assert.Equal(t, int64(2), byService["shop"].Entries)
	assert.Equal(t, entry.size()*2, byService["shop"].Bytes)
	assert.Equal(t, int64(1), byService["blog"].Entries)

	// A service drops out entirely when its last entry goes, rather than
	// lingering as a zero row.
	_, err := store.Purge(t.Context(), "blog", "")
	require.NoError(t, err)

	remaining := testStats(t, store, CacheStatsOptions{Count: true}).Local.Services
	require.Len(t, remaining, 1)
	assert.Equal(t, "shop", remaining[0].Service)
}

// The default store has nothing to arbitrate, but it does have plenty to report.
func TestMemoryStore_ReportsButDoesNotLease(t *testing.T) {
	store := testStatsStore(t, DefaultCacheMemorySize)

	_, isReporter := store.(CacheReporter)
	assert.True(t, isReporter, "sizing --cache-memory-size needs numbers")

	_, isLeaser := store.(CacheLeaser)
	assert.False(t, isLeaser, "a store nobody else can see has nothing to arbitrate")
}

// Reporting a convincing zero for a number the store could not read would be
// worse than saying so: an operator would size the cache against a lie.
func TestCacheStats_UnavailableNamesWhatIsUnknown(t *testing.T) {
	stats := CacheStats{Server: &CacheServerStats{Unavailable: []string{"used_bytes", "max_bytes"}}}

	assert.True(t, stats.Server.Unknown("used_bytes"))
	assert.True(t, stats.Server.Unknown("max_bytes"))
	assert.False(t, stats.Server.Unknown("keys"))
}

// The counter is what an alert watches: fresh evictions climbing means the
// budget is too small, while stale ones alone mean the cache is working.
func TestMemoryStats_ReportsEvictionsAsAMetric(t *testing.T) {
	tracker := installFakeTracker(t)

	entry := testStoredEntry("shop", "/products", "hello")
	store := testStatsStore(t, entry.size()*2)

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/products", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:three", testStoredEntry("shop", "/products", "hello")))

	assert.Equal(t, 1, tracker.cacheEvictionCount("shop", cacheEvictionFresh))
	assert.Equal(t, 0, tracker.cacheEvictionCount("shop", cacheEvictionStale))

	// An entry past its usefulness is labelled apart, so the two cannot be
	// confused on a dashboard. It has to be the least recently used one for the
	// budget to reach it, which means putting it in first.
	blog := testStoredEntry("blog", "/posts", "hello")
	blogStore := testStatsStore(t, blog.size()*2)

	stale := testStoredEntry("blog", "/posts", "hello")
	stale.FreshFor = time.Millisecond
	require.NoError(t, blogStore.Set(t.Context(), "kp:c:blog:one", stale))
	require.NoError(t, blogStore.Set(t.Context(), "kp:c:blog:two", testStoredEntry("blog", "/posts", "hello")))

	time.Sleep(5 * time.Millisecond)
	require.NoError(t, blogStore.Set(t.Context(), "kp:c:blog:three", testStoredEntry("blog", "/posts", "hello")))

	assert.Equal(t, 1, tracker.cacheEvictionCount("blog", cacheEvictionStale))
	assert.Equal(t, 0, tracker.cacheEvictionCount("blog", cacheEvictionFresh))
}
