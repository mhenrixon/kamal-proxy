package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCacheEntry(freshFor, staleWhileRevalidate time.Duration, storedAt time.Time) *CacheEntry {
	return &CacheEntry{
		Service:              "shop",
		Path:                 "/products",
		StatusCode:           http.StatusOK,
		Header:               http.Header{"Content-Type": {"text/html"}},
		Body:                 []byte("hello"),
		StoredAt:             storedAt,
		FreshFor:             freshFor,
		StaleWhileRevalidate: staleWhileRevalidate,
	}
}

func TestCacheEntry_Freshness(t *testing.T) {
	stored := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name             string
		freshFor         time.Duration
		stale            time.Duration
		initialAge       time.Duration
		elapsed          time.Duration
		expectedAge      time.Duration
		expectedFresh    bool
		expectedServable bool
	}{
		{name: "just stored", freshFor: time.Minute, elapsed: 0, expectedAge: 0, expectedFresh: true, expectedServable: true},
		{name: "within lifetime", freshFor: time.Minute, elapsed: 30 * time.Second, expectedAge: 30 * time.Second, expectedFresh: true, expectedServable: true},
		{name: "exactly at lifetime", freshFor: time.Minute, elapsed: time.Minute, expectedAge: time.Minute},
		{name: "expired with no stale window", freshFor: time.Minute, elapsed: 2 * time.Minute, expectedAge: 2 * time.Minute},
		{name: "inside stale window", freshFor: time.Second, stale: time.Minute, elapsed: 30 * time.Second, expectedAge: 30 * time.Second, expectedServable: true},
		{name: "past stale window", freshFor: time.Second, stale: time.Minute, elapsed: 2 * time.Minute, expectedAge: 2 * time.Minute},
		// An upstream Age header means the response was already old when it
		// reached us, and RFC 9111 counts that against the lifetime.
		{name: "upstream age counts", freshFor: time.Minute, initialAge: 50 * time.Second, elapsed: 20 * time.Second, expectedAge: 70 * time.Second},
		{name: "upstream age still fresh", freshFor: time.Minute, initialAge: 10 * time.Second, elapsed: 20 * time.Second, expectedAge: 30 * time.Second, expectedFresh: true, expectedServable: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := testCacheEntry(tt.freshFor, tt.stale, stored)
			entry.InitialAge = tt.initialAge
			now := stored.Add(tt.elapsed)

			assert.Equal(t, tt.expectedAge, entry.age(now))
			assert.Equal(t, tt.expectedFresh, entry.fresh(now))
			assert.Equal(t, tt.expectedServable, entry.servable(now))
			assert.Equal(t, !tt.expectedFresh && tt.expectedServable, entry.needsRevalidation(now))
		})
	}
}

// A clock that stepped backwards must not read as a negative age, which would
// make an expired entry look brand new.
func TestCacheEntry_AgeNeverGoesNegative(t *testing.T) {
	stored := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	entry := testCacheEntry(time.Minute, 0, stored)

	assert.Equal(t, time.Duration(0), entry.age(stored.Add(-time.Hour)))
}

func TestCacheEntry_TTLCoversTheStaleWindow(t *testing.T) {
	stored := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	assert.Equal(t, time.Minute, testCacheEntry(time.Minute, 0, stored).ttl())
	assert.Equal(t, 90*time.Second, testCacheEntry(time.Minute, 30*time.Second, stored).ttl())

	// Whatever the upstream age was, the entry may only live out the remainder.
	entry := testCacheEntry(time.Minute, 0, stored)
	entry.InitialAge = 20 * time.Second
	assert.Equal(t, 40*time.Second, entry.ttl())
}

func TestCacheEntry_Codec(t *testing.T) {
	stored := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	entry := testCacheEntry(time.Minute, 30*time.Second, stored)
	entry.Header.Add("Set-Cookie", "a=1")
	entry.Header.Add("Set-Cookie", "b=2")
	entry.InitialAge = 5 * time.Second

	encoded, err := encodeCacheEntry(entry)
	require.NoError(t, err)

	decoded, err := decodeCacheEntry(encoded)
	require.NoError(t, err)

	assert.Equal(t, entry.Service, decoded.Service)
	assert.Equal(t, entry.Path, decoded.Path)
	assert.Equal(t, entry.StatusCode, decoded.StatusCode)
	assert.Equal(t, entry.Body, decoded.Body)
	assert.Equal(t, entry.FreshFor, decoded.FreshFor)
	assert.Equal(t, entry.StaleWhileRevalidate, decoded.StaleWhileRevalidate)
	assert.Equal(t, entry.InitialAge, decoded.InitialAge)
	assert.True(t, entry.StoredAt.Equal(decoded.StoredAt))
	assert.Equal(t, []string{"a=1", "b=2"}, decoded.Header.Values("Set-Cookie"))
}

func TestCacheEntry_CodecRejectsGarbage(t *testing.T) {
	_, err := decodeCacheEntry([]byte("not an entry"))
	assert.Error(t, err)
}

func TestCacheEntry_Size(t *testing.T) {
	stored := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	entry := testCacheEntry(time.Minute, 0, stored)

	// Headers and the key material count too, or a cache of tiny bodies with
	// large headers would blow straight through its byte cap.
	assert.Greater(t, entry.size(), int64(len(entry.Body)))
}
