package server

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStoredEntry(service, path string, body string) *CacheEntry {
	return &CacheEntry{
		Service:    service,
		Path:       path,
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       []byte(body),
		StoredAt:   time.Now(),
		FreshFor:   time.Minute,
	}
}

func testMemoryStore(t *testing.T) CacheStore {
	t.Helper()

	store, err := NewCacheStore(CacheStoreConfig{URL: CacheStoreMemory})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

func testRedisStore(t *testing.T) (CacheStore, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)

	store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store, server
}

// Both stores answer the same contract, so the middleware behaves identically
// whether a fleet shares one cache or each node keeps its own.
func TestCacheStore_Contract(t *testing.T) {
	stores := map[string]func(t *testing.T) CacheStore{
		"memory": testMemoryStore,
		"redis": func(t *testing.T) CacheStore {
			store, _ := testRedisStore(t)
			return store
		},
	}

	for storeName, newStore := range stores {
		t.Run(storeName, func(t *testing.T) {
			t.Run("miss on an empty store", func(t *testing.T) {
				store := newStore(t)

				_, found := store.Get(t.Context(), "kp:c:shop:missing")
				assert.False(t, found)
			})

			t.Run("round trips an entry", func(t *testing.T) {
				store := newStore(t)
				entry := testStoredEntry("shop", "/products", "hello")
				entry.Header.Add("Set-Cookie", "a=1")
				entry.Header.Add("Set-Cookie", "b=2")

				require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", entry))

				found, ok := store.Get(t.Context(), "kp:c:shop:one")
				require.True(t, ok)
				assert.Equal(t, http.StatusOK, found.StatusCode)
				assert.Equal(t, []byte("hello"), found.Body)
				assert.Equal(t, "/products", found.Path)
				assert.Equal(t, []string{"a=1", "b=2"}, found.Header.Values("Set-Cookie"))
				assert.Equal(t, time.Minute, found.FreshFor)
			})

			t.Run("a second store replaces the first", func(t *testing.T) {
				store := newStore(t)

				require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "first")))
				require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "second")))

				found, ok := store.Get(t.Context(), "kp:c:shop:one")
				require.True(t, ok)
				assert.Equal(t, []byte("second"), found.Body)
			})

			t.Run("an entry with nothing left to live is not stored", func(t *testing.T) {
				store := newStore(t)
				entry := testStoredEntry("shop", "/products", "hello")
				entry.InitialAge = 2 * time.Minute

				require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", entry))

				_, found := store.Get(t.Context(), "kp:c:shop:one")
				assert.False(t, found)
			})

			t.Run("returned entries are detached from the store", func(t *testing.T) {
				store := newStore(t)
				require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))

				first, ok := store.Get(t.Context(), "kp:c:shop:one")
				require.True(t, ok)
				first.Header.Set("Content-Type", "text/plain")
				first.StatusCode = http.StatusTeapot

				second, ok := store.Get(t.Context(), "kp:c:shop:one")
				require.True(t, ok)
				assert.Equal(t, "text/html", second.Header.Get("Content-Type"))
				assert.Equal(t, http.StatusOK, second.StatusCode)
			})

			t.Run("purges one service without touching another", func(t *testing.T) {
				store := newStore(t)
				require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "a")))
				require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/about", "b")))
				require.NoError(t, store.Set(t.Context(), "kp:c:blog:one", testStoredEntry("blog", "/posts", "c")))

				purged, err := store.Purge(t.Context(), "shop", "")
				require.NoError(t, err)
				assert.Equal(t, 2, purged)

				_, found := store.Get(t.Context(), "kp:c:shop:one")
				assert.False(t, found)
				_, found = store.Get(t.Context(), "kp:c:shop:two")
				assert.False(t, found)
				_, found = store.Get(t.Context(), "kp:c:blog:one")
				assert.True(t, found)
			})

			t.Run("purges by path prefix", func(t *testing.T) {
				store := newStore(t)
				require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/assets/app.css", "a")))
				require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/assets/app.js", "b")))
				require.NoError(t, store.Set(t.Context(), "kp:c:shop:three", testStoredEntry("shop", "/products", "c")))

				purged, err := store.Purge(t.Context(), "shop", "/assets")
				require.NoError(t, err)
				assert.Equal(t, 2, purged)

				_, found := store.Get(t.Context(), "kp:c:shop:three")
				assert.True(t, found)
			})

			t.Run("purging an unknown service reports nothing removed", func(t *testing.T) {
				store := newStore(t)

				purged, err := store.Purge(t.Context(), "nope", "")
				require.NoError(t, err)
				assert.Equal(t, 0, purged)
			})

			t.Run("survives concurrent use", func(t *testing.T) {
				store := newStore(t)

				var wg sync.WaitGroup
				for i := range 20 {
					wg.Go(func() {
						key := fmt.Sprintf("kp:c:shop:%d", i%5)
						_ = store.Set(t.Context(), key, testStoredEntry("shop", "/products", "hello"))
						store.Get(t.Context(), key)
					})
				}
				wg.Wait()
			})
		})
	}
}

func TestMemoryCacheStore_EvictsLeastRecentlyUsedOverBudget(t *testing.T) {
	entry := testStoredEntry("shop", "/products", "hello")
	// Room for exactly two entries, so storing a third has to displace one.
	store, err := NewCacheStore(CacheStoreConfig{URL: CacheStoreMemory, MemorySize: entry.size() * 2})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/products", "hello")))

	// Touching the first makes the second the least recently used.
	_, found := store.Get(t.Context(), "kp:c:shop:one")
	require.True(t, found)

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:three", testStoredEntry("shop", "/products", "hello")))

	_, found = store.Get(t.Context(), "kp:c:shop:two")
	assert.False(t, found, "the least recently used entry should have been evicted")

	_, found = store.Get(t.Context(), "kp:c:shop:one")
	assert.True(t, found)
	_, found = store.Get(t.Context(), "kp:c:shop:three")
	assert.True(t, found)
}

// An entry too large to ever fit must not empty the cache trying to make room.
func TestMemoryCacheStore_RefusesAnEntryLargerThanTheBudget(t *testing.T) {
	small := testStoredEntry("shop", "/products", "hello")
	store, err := NewCacheStore(CacheStoreConfig{URL: CacheStoreMemory, MemorySize: small.size() + 10})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	require.NoError(t, store.Set(t.Context(), "kp:c:shop:small", small))

	oversized := testStoredEntry("shop", "/big", "")
	oversized.Body = make([]byte, small.size()*4)
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:big", oversized))

	_, found := store.Get(t.Context(), "kp:c:shop:big")
	assert.False(t, found)

	_, found = store.Get(t.Context(), "kp:c:shop:small")
	assert.True(t, found, "an oversized entry should not evict what already fit")
}

func TestMemoryCacheStore_DropsEntriesPastTheirStaleWindow(t *testing.T) {
	store := testMemoryStore(t)

	entry := testStoredEntry("shop", "/products", "hello")
	entry.FreshFor = time.Millisecond
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", entry))

	assert.Eventually(t, func() bool {
		_, found := store.Get(t.Context(), "kp:c:shop:one")
		return !found
	}, time.Second, 5*time.Millisecond)
}

func TestRedisCacheStore_ExpiresKeysOnTheServer(t *testing.T) {
	store, server := testRedisStore(t)

	entry := testStoredEntry("shop", "/products", "hello")
	entry.FreshFor = 30 * time.Second
	entry.StaleWhileRevalidate = 30 * time.Second
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", entry))

	_, found := store.Get(t.Context(), "kp:c:shop:one")
	require.True(t, found)

	// Redis owns expiry for the shared store, so nothing has to sweep it.
	server.FastForward(time.Minute)

	_, found = store.Get(t.Context(), "kp:c:shop:one")
	assert.False(t, found)
}

// A Redis that is down must cost requests a cache, not a 502.
func TestRedisCacheStore_FailsOpenWhenTheServerIsUnreachable(t *testing.T) {
	store, server := testRedisStore(t)
	require.NoError(t, store.Set(t.Context(), "kp:c:shop:one", testStoredEntry("shop", "/products", "hello")))

	server.Close()

	_, found := store.Get(t.Context(), "kp:c:shop:one")
	assert.False(t, found, "an unreachable store reads as a miss")

	assert.Error(t, store.Set(t.Context(), "kp:c:shop:two", testStoredEntry("shop", "/products", "hello")))

	_, err := store.Purge(t.Context(), "shop", "")
	assert.Error(t, err)
}

func TestRedisCacheStore_HonorsTheConfiguredTimeout(t *testing.T) {
	server := miniredis.RunT(t)

	store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr(), Timeout: time.Nanosecond})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	// Every operation has to give up rather than hold a request open.
	_, found := store.Get(t.Context(), "kp:c:shop:one")
	assert.False(t, found)
}

func TestNewCacheStore(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedError string
	}{
		{name: "empty defaults to memory", url: ""},
		{name: "memory", url: CacheStoreMemory},
		{name: "redis", url: "redis://localhost:6379/0"},
		{name: "redis over tls", url: "rediss://localhost:6379"},
		{name: "unknown scheme", url: "memcache://localhost:11211", expectedError: "cache-store must be"},
		{name: "not a url", url: "localhost:6379", expectedError: "cache-store must be"},
		{name: "malformed redis url", url: "redis://user@:pass@host:notaport", expectedError: "cache-store"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ParseCacheStoreURL(tt.url)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}
