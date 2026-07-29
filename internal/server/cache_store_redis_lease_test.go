package server

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRedisFleet returns two stores over one miniredis, which is the shape of a
// two-node fleet sharing a cache.
func testRedisFleet(t *testing.T) (CacheLeaser, CacheLeaser, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	newNode := func() CacheLeaser {
		store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
		require.NoError(t, err)
		t.Cleanup(func() { store.Close() })

		leaser, ok := store.(CacheLeaser)
		require.True(t, ok, "the shared store should arbitrate fetches")
		return leaser
	}

	return newNode(), newNode(), server
}

const testEntryKey = cacheKeyPrefix + "shop:abc"

func TestRedisLease_SecondProxyIsDenied(t *testing.T) {
	first, second, _ := testRedisFleet(t)

	lease := first.AcquireLease(t.Context(), testEntryKey, time.Minute)
	assert.Equal(t, CacheLeaseAcquired, lease.Outcome)
	assert.True(t, lease.mine())

	denied := second.AcquireLease(t.Context(), testEntryKey, time.Minute)
	assert.Equal(t, CacheLeaseTaken, denied.Outcome)
	assert.True(t, denied.taken())
}

func TestRedisLease_ReleaseFreesTheKeyForTheNextProxy(t *testing.T) {
	first, second, _ := testRedisFleet(t)

	lease := first.AcquireLease(t.Context(), testEntryKey, time.Minute)
	require.Equal(t, CacheLeaseAcquired, lease.Outcome)

	first.ReleaseLease(t.Context(), lease)

	assert.Equal(t, CacheLeaseAcquired, second.AcquireLease(t.Context(), testEntryKey, time.Minute).Outcome)
}

// A holder whose lease expired must not be able to drop its successor's claim --
// that would hand a third proxy the fetch the lease exists to prevent.
func TestRedisLease_ReleaseOfAnExpiredLeaseLeavesTheSuccessorAlone(t *testing.T) {
	first, second, server := testRedisFleet(t)

	stale := first.AcquireLease(t.Context(), testEntryKey, time.Second)
	require.Equal(t, CacheLeaseAcquired, stale.Outcome)

	server.FastForward(2 * time.Second)

	successor := second.AcquireLease(t.Context(), testEntryKey, time.Minute)
	require.Equal(t, CacheLeaseAcquired, successor.Outcome)

	// The original holder finally finishes and releases what it thinks is its
	// lease.
	first.ReleaseLease(t.Context(), stale)

	assert.Equal(t, CacheLeaseTaken, first.AcquireLease(t.Context(), testEntryKey, time.Minute).Outcome,
		"the successor's lease should have survived")
}

// A node killed mid-fetch leaves its claim behind; nothing sweeps it, so Redis
// has to forget it on its own.
func TestRedisLease_ExpiresOnItsOwn(t *testing.T) {
	first, second, server := testRedisFleet(t)

	require.Equal(t, CacheLeaseAcquired, first.AcquireLease(t.Context(), testEntryKey, time.Second).Outcome)
	require.Equal(t, CacheLeaseTaken, second.AcquireLease(t.Context(), testEntryKey, time.Second).Outcome)

	server.FastForward(2 * time.Second)

	assert.Equal(t, CacheLeaseAcquired, second.AcquireLease(t.Context(), testEntryKey, time.Second).Outcome)
}

func TestRedisLease_ProbeReportsEntryAndHolderInOneCall(t *testing.T) {
	tests := []struct {
		name          string
		storeEntry    bool
		takeLease     bool
		expectedEntry bool
		expectedHeld  bool
	}{
		{name: "nothing at all", expectedEntry: false, expectedHeld: false},
		{name: "lease held, no entry yet", takeLease: true, expectedHeld: true},
		{name: "entry published, lease released", storeEntry: true, expectedEntry: true},
		{name: "entry and lease both present", storeEntry: true, takeLease: true, expectedEntry: true, expectedHeld: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, second, _ := testRedisFleet(t)
			store := first.(CacheStore)

			if tt.storeEntry {
				require.NoError(t, store.Set(t.Context(), testEntryKey, testStoredEntry("shop", "/p", "hello")))
			}
			if tt.takeLease {
				require.Equal(t, CacheLeaseAcquired, first.AcquireLease(t.Context(), testEntryKey, time.Minute).Outcome)
			}

			entry, held := second.ProbeLease(t.Context(), testEntryKey)

			assert.Equal(t, tt.expectedEntry, entry != nil)
			assert.Equal(t, tt.expectedHeld, held)
		})
	}
}

// Constraint 1: a store that is down must cost a duplicate fetch, never a stall.
func TestRedisLease_FailsOpenWhenTheStoreIsUnreachable(t *testing.T) {
	first, _, server := testRedisFleet(t)
	server.Close()

	lease := first.AcquireLease(t.Context(), testEntryKey, time.Minute)
	assert.Equal(t, CacheLeaseUnavailable, lease.Outcome)
	assert.False(t, lease.taken(), "an unreachable store must grant, not withhold")

	entry, held := first.ProbeLease(t.Context(), testEntryKey)
	assert.Nil(t, entry)
	assert.False(t, held, "a store that stopped answering must stop a caller waiting")

	// Releasing a lease we never really held must not panic or block.
	first.ReleaseLease(t.Context(), lease)
}

func TestRedisLease_FailsOpenWhenTheStoreIsSlow(t *testing.T) {
	server := miniredis.RunT(t)
	store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr(), Timeout: time.Nanosecond})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	leaser := store.(CacheLeaser)
	assert.Equal(t, CacheLeaseUnavailable, leaser.AcquireLease(t.Context(), testEntryKey, time.Minute).Outcome)
}

// A dead store should cost one probe per cooldown, not a timeout on every miss.
func TestRedisLease_StopsAskingAStoreThatKeepsFailing(t *testing.T) {
	first, _, server := testRedisFleet(t)
	server.Close()

	for range cacheLeaseBreakerThreshold {
		assert.Equal(t, CacheLeaseUnavailable, first.AcquireLease(t.Context(), testEntryKey, time.Minute).Outcome)
	}

	lease := first.AcquireLease(t.Context(), testEntryKey, time.Minute)
	assert.Equal(t, CacheLeaseDeferred, lease.Outcome, "the breaker should have opened")
	assert.False(t, lease.taken(), "deferring still grants the fetch")
}

// Purge scans the entry namespace and deletes what it matches without reading
// it. A lease caught by that scan would be dropped mid-fetch and counted in the
// number the operator is shown.
func TestRedisLease_PurgeLeavesLeasesAlone(t *testing.T) {
	first, _, _ := testRedisFleet(t)
	store := first.(CacheStore)

	require.NoError(t, store.Set(t.Context(), testEntryKey, testStoredEntry("shop", "/p", "hello")))
	lease := first.AcquireLease(t.Context(), testEntryKey, time.Minute)
	require.Equal(t, CacheLeaseAcquired, lease.Outcome)

	purged, err := store.Purge(t.Context(), "shop", "")
	require.NoError(t, err)
	assert.Equal(t, 1, purged, "only the entry should be counted")

	_, held := first.ProbeLease(t.Context(), testEntryKey)
	assert.True(t, held, "the lease should have survived the purge")
}
