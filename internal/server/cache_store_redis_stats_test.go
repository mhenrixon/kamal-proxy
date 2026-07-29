package server

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRedisStatsStore(t *testing.T) (CacheStore, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store, server
}

// A managed Redis often restricts INFO. Reporting zero for what it withheld
// would have an operator sizing the cache against a lie, so the withheld fields
// name themselves instead.
func TestRedisStats_ReportsKeysAndDegradesWhenInfoIsRestricted(t *testing.T) {
	store, _ := testRedisStatsStore(t)

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/about", "hello")))

	stats := testStats(t, store, CacheStatsOptions{})

	assert.Equal(t, CacheStoreRedis, stats.Store)
	assert.True(t, stats.Shared, "other proxies write to the same store")
	assert.False(t, stats.Local.Counted, "counting a shared keyspace is opt-in")
	assert.Equal(t, int64(0), stats.Local.MaxBytes, "a shared store is bounded by its own maxmemory")

	require.NotNil(t, stats.Server)
	assert.Equal(t, int64(2), stats.Server.Keys, "DBSIZE is O(1) and always available")

	// miniredis rejects `INFO memory`, which is exactly the managed-Redis case.
	assert.True(t, stats.Server.Unknown("used_bytes"))
	assert.True(t, stats.Server.Unknown("max_bytes"))
	assert.True(t, stats.Server.Unknown("eviction_policy"))
	assert.Equal(t, int64(0), stats.Server.UsedBytes, "unknown, and the Unavailable list is what says so")
}

func TestRedisStats_CountsThisCachesEntriesWhenAsked(t *testing.T) {
	store, _ := testRedisStatsStore(t)

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/about", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:blog:one", testStoredEntry("blog", "/posts", "hello")))

	// A live lease and a foreign key share the database, and neither is this
	// cache's content.
	require.Equal(t, CacheLeaseAcquired,
		store.(CacheLeaser).AcquireLease(t.Context(), "kp:c:shop:one", time.Minute).Outcome)

	stats := testStats(t, store, CacheStatsOptions{Count: true})

	assert.True(t, stats.Local.Counted)
	assert.Equal(t, int64(3), stats.Local.Entries, "only kp:c: keys are this cache's entries")
	assert.Greater(t, stats.Local.Bytes, int64(0))

	require.Len(t, stats.Local.Services, 2)
	byService := map[string]CacheServiceStats{}
	for _, service := range stats.Local.Services {
		byService[service.Service] = service
	}
	assert.Equal(t, int64(2), byService["shop"].Entries)
	assert.Equal(t, int64(1), byService["blog"].Entries)

	// The lease is still counted by DBSIZE, because that really is what the
	// server holds.
	assert.Equal(t, int64(4), stats.Server.Keys)
}

// Every other store method fails open. This one does not: an operator asking how
// full the cache is deserves the failure rather than a convincing zero.
func TestRedisStats_ReturnsItsErrorRatherThanAConvincingZero(t *testing.T) {
	store, server := testRedisStatsStore(t)
	server.Close()

	reporter, ok := store.(CacheReporter)
	require.True(t, ok)

	_, err := reporter.Stats(t.Context(), CacheStatsOptions{})
	assert.Error(t, err, "a stats read reports its errors, unlike the request path")
}

// The one path miniredis cannot cover end to end: it rejects `INFO memory`, so
// the parser is exercised against a captured payload from a real server.
func TestParseRedisInfo(t *testing.T) {
	payload := "# Memory\r\n" +
		"used_memory:1048576\r\n" +
		"used_memory_human:1.00M\r\n" +
		"maxmemory:4294967296\r\n" +
		"maxmemory_policy:allkeys-lru\r\n" +
		"\r\n"

	fields := parseRedisInfo(payload)

	assert.Equal(t, "1048576", fields["used_memory"])
	assert.Equal(t, "4294967296", fields["maxmemory"])
	assert.Equal(t, "allkeys-lru", fields["maxmemory_policy"])

	// A section heading is not a field, and an absent field is absent rather
	// than an empty string that would read as zero downstream.
	assert.NotContains(t, fields, "# Memory")
	_, present := fields["mem_fragmentation_ratio"]
	assert.False(t, present)
}
