package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testFileStore(t *testing.T, maxBytes int64) (*fileCacheStore, string) {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "cache")

	store, err := newFileCacheStore(dir, maxBytes)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	return store, dir
}

func testEntry(service, path string, body string, freshFor time.Duration) *CacheEntry {
	return &CacheEntry{
		Service:    service,
		Path:       path,
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/css"}},
		Body:       []byte(body),
		StoredAt:   time.Now(),
		FreshFor:   freshFor,
	}
}

func TestFileCacheStore_RoundTripsAnEntry(t *testing.T) {
	store, _ := testFileStore(t, 0)
	ctx := context.Background()

	entry := testEntry("app", "/assets/app.css", "body{}", time.Hour)
	require.NoError(t, store.Set(ctx, "k1", entry))

	got, found := store.Get(ctx, "k1")
	require.True(t, found)
	assert.Equal(t, "app", got.Service)
	assert.Equal(t, "/assets/app.css", got.Path)
	assert.Equal(t, http.StatusOK, got.StatusCode)
	assert.Equal(t, "body{}", string(got.Body))
	assert.Equal(t, "text/css", got.Header.Get("Content-Type"))
}

func TestFileCacheStore_MissingKeyIsAMiss(t *testing.T) {
	store, _ := testFileStore(t, 0)

	_, found := store.Get(context.Background(), "absent")
	assert.False(t, found)
}

// Matches the Set contract: "An entry with nothing left to live is dropped
// rather than stored."
func TestFileCacheStore_DropsAnEntryWithNothingLeftToLive(t *testing.T) {
	store, dir := testFileStore(t, 0)
	ctx := context.Background()

	expired := testEntry("app", "/gone", "x", 0)
	expired.StoredAt = time.Now().Add(-time.Hour)

	require.NoError(t, store.Set(ctx, "dead", expired))

	_, found := store.Get(ctx, "dead")
	assert.False(t, found)

	written, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, written, "nothing should reach disk for an entry that cannot answer")
}

// The whole point of the issue: a proxy restart must not empty the cache, so a
// sleeping app is not woken to re-serve a file that has not changed.
func TestFileCacheStore_SurvivesAReopen(t *testing.T) {
	store, dir := testFileStore(t, 0)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "asset", testEntry("app", "/assets/app.js", "console.log(1)", time.Hour)))
	require.NoError(t, store.Close())

	reopened, err := newFileCacheStore(dir, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	got, found := reopened.Get(ctx, "asset")
	require.True(t, found, "a reopened store must still hold what the old one wrote")
	assert.Equal(t, "console.log(1)", string(got.Body))
	assert.Equal(t, "/assets/app.js", got.Path, "the index has to be rebuilt from disk, not just the body")
}

// An entry whose stale window has passed is not resurrected by a restart.
func TestFileCacheStore_DoesNotServeAnExpiredEntryAfterAReopen(t *testing.T) {
	store, dir := testFileStore(t, 0)
	ctx := context.Background()

	entry := testEntry("app", "/short", "x", 50*time.Millisecond)
	require.NoError(t, store.Set(ctx, "short", entry))
	require.NoError(t, store.Close())

	time.Sleep(120 * time.Millisecond)

	reopened, err := newFileCacheStore(dir, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	_, found := reopened.Get(ctx, "short")
	assert.False(t, found)
}

func TestFileCacheStore_Purge(t *testing.T) {
	tests := []struct {
		name       string
		service    string
		pathPrefix string
		expected   int
		remaining  []string
	}{
		{name: "whole service", service: "app", expected: 2, remaining: []string{"other"}},
		{name: "by path prefix", service: "app", pathPrefix: "/assets", expected: 1, remaining: []string{"page", "other"}},
		{name: "unknown service", service: "nobody", expected: 0, remaining: []string{"asset", "page", "other"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := testFileStore(t, 0)
			ctx := context.Background()

			require.NoError(t, store.Set(ctx, "asset", testEntry("app", "/assets/a.css", "a", time.Hour)))
			require.NoError(t, store.Set(ctx, "page", testEntry("app", "/index.html", "p", time.Hour)))
			require.NoError(t, store.Set(ctx, "other", testEntry("other", "/assets/b.css", "b", time.Hour)))

			purged, err := store.Purge(ctx, tt.service, tt.pathPrefix)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, purged)

			for _, key := range tt.remaining {
				_, found := store.Get(ctx, key)
				assert.True(t, found, "%s should have survived", key)
			}
		})
	}
}

// A purge has to reach the disk, not just the index, or a restart brings the
// purged entries back.
func TestFileCacheStore_PurgeSurvivesAReopen(t *testing.T) {
	store, dir := testFileStore(t, 0)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "asset", testEntry("app", "/a.css", "a", time.Hour)))
	_, err := store.Purge(ctx, "app", "")
	require.NoError(t, err)
	require.NoError(t, store.Close())

	reopened, err := newFileCacheStore(dir, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	_, found := reopened.Get(ctx, "asset")
	assert.False(t, found, "a purged entry must not come back after a restart")
}

func TestFileCacheStore_EvictsToStayInsideItsBudget(t *testing.T) {
	ctx := context.Background()

	// Sized from the real accounting rather than a guess: size() adds a flat
	// per-entry overhead on top of the body, so a budget picked by eye rejects
	// entries as oversized instead of storing and evicting them.
	body := string(make([]byte, 150))
	entrySize := testEntry("app", "/1", body, time.Hour).size()

	// Room for two entries, not three.
	store, _ := testFileStore(t, entrySize*2+entrySize/2)
	require.NoError(t, store.Set(ctx, "one", testEntry("app", "/1", body, time.Hour)))
	require.NoError(t, store.Set(ctx, "two", testEntry("app", "/2", body, time.Hour)))

	// Touch "two" so the least recently used is "one".
	_, _ = store.Get(ctx, "two")

	require.NoError(t, store.Set(ctx, "three", testEntry("app", "/3", body, time.Hour)))

	_, foundOne := store.Get(ctx, "one")
	_, foundThree := store.Get(ctx, "three")
	assert.False(t, foundOne, "the least recently used entry should have been evicted")
	assert.True(t, foundThree)

	stats, err := store.Stats(ctx, CacheStatsOptions{})
	require.NoError(t, err)
	assert.Equal(t, CacheStoreFile, stats.Store)
	assert.Positive(t, stats.Local.EvictedFresh+stats.Local.EvictedStale, "an eviction must be observable")
	assert.LessOrEqual(t, stats.Local.Bytes, stats.Local.MaxBytes, "the store must stay inside its budget")
}

func TestFileCacheStore_StatsReportWhatIsHeld(t *testing.T) {
	store, _ := testFileStore(t, 4096)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "a", testEntry("app", "/a", "aaa", time.Hour)))
	require.NoError(t, store.Set(ctx, "b", testEntry("other", "/b", "bbb", time.Hour)))

	stats, err := store.Stats(ctx, CacheStatsOptions{Count: true})
	require.NoError(t, err)

	assert.Equal(t, CacheStoreFile, stats.Store)
	assert.False(t, stats.Shared, "a directory on one host is not a fleet-shared store")
	assert.True(t, stats.Local.Counted)
	assert.Equal(t, int64(2), stats.Local.Entries)
	assert.Equal(t, int64(4096), stats.Local.MaxBytes)
	assert.Positive(t, stats.Local.Bytes)
	assert.Len(t, stats.Local.Services, 2)
}

// The CacheStore contract: "a store that is unreachable turns every lookup into
// a miss and every write into a logged error, and never into a failed request."
func TestFileCacheStore_FailsOpen(t *testing.T) {
	ctx := context.Background()

	t.Run("a corrupt entry file is a miss, not an error", func(t *testing.T) {
		store, _ := testFileStore(t, 0)
		require.NoError(t, store.Set(ctx, "k", testEntry("app", "/a", "a", time.Hour)))

		path, ok := store.pathForKey("k")
		require.True(t, ok)
		require.NoError(t, os.WriteFile(path, []byte("not a gob"), 0600))

		_, found := store.Get(ctx, "k")
		assert.False(t, found, "a corrupt file must read as a miss")
	})

	t.Run("a directory removed underneath the store is a miss, not an error", func(t *testing.T) {
		store, dir := testFileStore(t, 0)
		require.NoError(t, store.Set(ctx, "k", testEntry("app", "/a", "a", time.Hour)))
		require.NoError(t, os.RemoveAll(dir))

		_, found := store.Get(ctx, "k")
		assert.False(t, found)

		// And a write against the missing directory reports rather than panics.
		assert.NotPanics(t, func() {
			_ = store.Set(ctx, "k2", testEntry("app", "/b", "b", time.Hour))
		})
	})

	t.Run("a corrupt file on disk does not stop the store opening", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "cache")
		require.NoError(t, os.MkdirAll(dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "garbage"+fileCacheEntrySuffix), []byte("junk"), 0600))

		store, err := newFileCacheStore(dir, 0)
		require.NoError(t, err, "one unreadable file must not make the whole cache unopenable")
		t.Cleanup(func() { _ = store.Close() })

		require.NoError(t, store.Set(ctx, "k", testEntry("app", "/a", "a", time.Hour)))
		_, found := store.Get(ctx, "k")
		assert.True(t, found)
	})
}

// A store is reached from concurrent request goroutines.
func TestFileCacheStore_IsSafeUnderConcurrentUse(t *testing.T) {
	store, _ := testFileStore(t, 0)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				key := "shared"
				_ = store.Set(ctx, key, testEntry("app", "/a", "body", time.Hour))
				_, _ = store.Get(ctx, key)
				_, _ = store.Purge(ctx, "nobody", "")
				_, _ = store.Stats(ctx, CacheStatsOptions{})
				_ = i
			}
		}()
	}
	wg.Wait()
}

func TestParseCacheStoreURL_AcceptsFileScheme(t *testing.T) {
	assert.NoError(t, ParseCacheStoreURL("file:///var/lib/kamal-proxy/cache"))
	assert.Error(t, ParseCacheStoreURL("file://"), "a file store with no path is a typo, not a default")
}

func TestNewCacheStore_BuildsAFileStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")

	store, err := NewCacheStore(CacheStoreConfig{URL: "file://" + dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	assert.IsType(t, &fileCacheStore{}, store)

	// A file store is not fleet-shared, so it deliberately does not arbitrate
	// fetches -- the in-process single flight already does on one host.
	_, isLeaser := store.(CacheLeaser)
	assert.False(t, isLeaser, "a single-host store must not claim to be a fleet leaser")
}
