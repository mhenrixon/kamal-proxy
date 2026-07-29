package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func varyingHandler(origin *atomic.Int64, field string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin != nil {
			origin.Add(1)
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", field)
		fmt.Fprint(w, r.Header.Get(field))
	}
}

func requestVarying(field, value string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	req.Header.Set(field, value)
	return req
}

// THE test. The inflight group is keyed on the resource, but nobody knows which
// variant a request is until the response arrives -- so a burst can enrol two
// requests that differ in a Vary dimension. Serving the leader's variant to the
// follower would hand a real client somebody else's content.
func TestCacheVary_ColdBurstDoesNotServeLeadersVariantToFollower(t *testing.T) {
	const clients = 2

	arrived := make(chan struct{}, clients)
	release := make(chan struct{})

	var origin atomic.Int64
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		arrived <- struct{}{}
		<-release

		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "Accept")
		fmt.Fprint(w, r.Header.Get("Accept"))
	})

	bodies := make([]string, clients)
	accepts := []string{"text/html", "application/json"}

	var wg sync.WaitGroup
	for i, accept := range accepts {
		wg.Go(func() {
			bodies[i] = sendCacheRequest(middleware, requestVarying("Accept", accept)).Body.String()
		})
	}

	// Let the first reach the origin, then release both.
	<-arrived
	time.Sleep(40 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, "text/html", bodies[0], "each client gets the representation it asked for")
	assert.Equal(t, "application/json", bodies[1])
	assert.Equal(t, int64(2), origin.Load(), "two variants cannot share one fetch")
}

// Once the index is warm, each variant is served its own body and neither costs
// the origin anything.
func TestCacheVary_WarmIndexServesEachVariantItsOwnBody(t *testing.T) {
	var origin atomic.Int64
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, varyingHandler(&origin, "Accept-Language"))

	for _, language := range []string{"en", "sv", "de"} {
		response := sendCacheRequest(middleware, requestVarying("Accept-Language", language))
		assert.Equal(t, language, response.Body.String())
		assert.Equal(t, cacheStatusMiss, response.Header().Get("X-Cache"))
	}
	require.Equal(t, int64(3), origin.Load())

	for _, language := range []string{"en", "sv", "de"} {
		response := sendCacheRequest(middleware, requestVarying("Accept-Language", language))
		assert.Equal(t, language, response.Body.String(), "a warm variant answers its own client")
		assert.Equal(t, cacheStatusHit, response.Header().Get("X-Cache"))
	}
	assert.Equal(t, int64(3), origin.Load(), "and costs the origin nothing")
}

// An index has no status and no body. Replaying one would call WriteHeader(0),
// which panics net/http -- so every serve path has to refuse it.
func TestCacheVary_IndexIsNeverReplayedToAClient(t *testing.T) {
	store := testMemoryStore(t)

	var origin atomic.Int64
	middleware := WithCacheMiddleware(CacheConfig{
		Service: t.Name(),
		Options: CacheOptions{Enabled: true},
		Store:   store,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte("real"))
	}))

	// Plant an index whose variants were never written.
	key := cacheKey(t.Name(), "", httptest.NewRequest(http.MethodGet, "http://example.com/p", nil), CacheOptions{Enabled: true})
	require.NoError(t, store.Set(t.Context(), key, &CacheEntry{
		Service:  t.Name(),
		Path:     "/p",
		VaryOn:   []string{"accept-language"},
		Variants: []string{"deadbeefdeadbeef"},
		StoredAt: time.Now(),
		FreshFor: time.Hour,
	}))

	response := getCached(middleware, "http://example.com/p")

	assert.Equal(t, http.StatusOK, response.Code, "an index must never be written out as a response")
	assert.Equal(t, "real", response.Body.String())
	assert.Equal(t, int64(1), origin.Load())
}

func TestEntryAnswers(t *testing.T) {
	primary := "kp:c:shop:abc"

	varying := func(varyOn []string, r *http.Request) *CacheEntry {
		return &CacheEntry{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			VaryOn:     varyOn,
			VariantKey: variantKeyFor(primary, varyOn, r),
		}
	}

	english := requestVarying("Accept-Language", "en")
	swedish := requestVarying("Accept-Language", "sv")

	both := func(accept string) *http.Request {
		r := requestVarying("Accept-Language", "en")
		r.Header.Set("Accept", accept)
		return r
	}
	bothHTML, bothJSON := both("text/html"), both("application/json")

	tests := []struct {
		name     string
		entry    *CacheEntry
		request  *http.Request
		expected bool
	}{
		{name: "nil", request: english},
		{name: "an index is not a response", entry: &CacheEntry{VaryOn: []string{"accept-language"}}, request: english},
		{
			name:     "a non-varying entry answers anyone",
			entry:    &CacheEntry{StatusCode: http.StatusOK, Header: http.Header{}},
			request:  english,
			expected: true,
		},
		{
			name:     "its own variant",
			entry:    varying([]string{"accept-language"}, english),
			request:  english,
			expected: true,
		},
		{
			// The whole point: another client's variant is refused.
			name:    "another variant",
			entry:   varying([]string{"accept-language"}, english),
			request: swedish,
		},
		{
			// Every dimension has to match, not just the one that led here: an
			// entry stored for en+html does not answer en+json.
			name:    "matching one dimension is not enough",
			entry:   varying([]string{"accept", "accept-language"}, bothHTML),
			request: bothJSON,
		},
		{
			name:     "matching every dimension",
			entry:    varying([]string{"accept", "accept-language"}, bothHTML),
			request:  bothHTML,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, entryAnswers(tt.entry, primary, tt.request))
		})
	}
}

// A Rack::Deflater response -- Content-Encoding plus Vary: Accept-Encoding --
// is the case that used to cache nothing at all without a flag.
func TestCacheVary_TargetEncodedResponseIsStoredWithNoFlags(t *testing.T) {
	var origin atomic.Int64
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Write([]byte("compressed"))
	})

	gzipped := func() *http.Request { return requestVarying("Accept-Encoding", "gzip, deflate, br") }

	require.Equal(t, cacheStatusMiss, sendCacheRequest(middleware, gzipped()).Header().Get("X-Cache"))
	assert.Equal(t, cacheStatusHit, sendCacheRequest(middleware, gzipped()).Header().Get("X-Cache"))
	assert.Equal(t, int64(1), origin.Load(), "no flag needed any more")

	// And a client that cannot read gzip is never handed those bytes.
	plain := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	assert.Equal(t, cacheStatusMiss, sendCacheRequest(middleware, plain).Header().Get("X-Cache"))
}

// --cache-vary-cookie names cookies for the PRIMARY key. It must not be read as
// permission to key on Vary: Cookie -- Django sets that by default, so an
// existing deployment would start sharing personalised pages on upgrade with no
// config change at all.
func TestCacheVary_CookieIsRefusedEvenWithVaryCookieSet(t *testing.T) {
	tracker := installFakeTracker(t)

	options := CacheOptions{Enabled: true, VaryCookies: []string{"locale"}}
	var origin atomic.Int64
	middleware, _ := testCacheHandler(t, options, func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "Cookie")
		fmt.Fprint(w, r.Header.Get("Cookie"))
	})

	for _, session := range []string{"session=a", "session=b"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
		req.Header.Set("Cookie", session)
		assert.Equal(t, session, sendCacheRequest(middleware, req).Body.String())
	}

	assert.Equal(t, int64(2), origin.Load(), "nothing may be stored")
	assert.Equal(t, 2, tracker.cacheRefusalCount(t.Name(), string(cacheRefusalVaryUnkeyable)))
}

// countingStore proves the common path did not regress, which is the whole
// justification for an index being a separate record.
type countingStore struct {
	CacheStore
	gets atomic.Int64
	sets atomic.Int64
}

func (s *countingStore) Get(ctx context.Context, key string) (*CacheEntry, bool) {
	s.gets.Add(1)
	return s.CacheStore.Get(ctx, key)
}

func (s *countingStore) Set(ctx context.Context, key string, entry *CacheEntry) error {
	s.sets.Add(1)
	return s.CacheStore.Set(ctx, key, entry)
}

func TestCacheVary_NonVaryingCostsExactlyOneGetAndOneSet(t *testing.T) {
	store := &countingStore{CacheStore: testMemoryStore(t)}
	middleware := WithCacheMiddleware(CacheConfig{
		Service: t.Name(),
		Options: CacheOptions{Enabled: true},
		Store:   store,
	}, cacheableHandler("hello"))

	getCached(middleware, "http://example.com/p")
	assert.Equal(t, int64(1), store.gets.Load(), "a miss looks once")
	assert.Equal(t, int64(1), store.sets.Load(), "and writes once -- no index for a resource that does not negotiate")

	getCached(middleware, "http://example.com/p")
	assert.Equal(t, int64(2), store.gets.Load(), "a hit looks once")
	assert.Equal(t, int64(1), store.sets.Load())
}

func TestCacheVary_VaryingCostsTwoGets(t *testing.T) {
	store := &countingStore{CacheStore: testMemoryStore(t)}
	middleware := WithCacheMiddleware(CacheConfig{
		Service: t.Name(),
		Options: CacheOptions{Enabled: true},
		Store:   store,
	}, varyingHandler(nil, "Accept-Language"))

	sendCacheRequest(middleware, requestVarying("Accept-Language", "en"))
	store.gets.Store(0)
	store.sets.Store(0)

	sendCacheRequest(middleware, requestVarying("Accept-Language", "en"))
	assert.Equal(t, int64(2), store.gets.Load(), "one to find the index, one to read the variant")
	assert.Equal(t, int64(0), store.sets.Load())
}

func TestAdmitVariant(t *testing.T) {
	primary := "kp:c:shop:abc"
	options := CacheOptions{Enabled: true, MaxVariants: 2}

	entryFor := func(language string) *CacheEntry {
		r := requestVarying("Accept-Language", language)
		return &CacheEntry{
			Service: "shop", Path: "/p", StatusCode: http.StatusOK,
			VaryOn: []string{"accept-language"}, VariantKey: variantKeyFor(primary, []string{"accept-language"}, r),
			FreshFor: time.Minute,
		}
	}

	// Cold: the first variant publishes the index.
	index, admitted := admitVariant(options, nil, entryFor("en"), primary)
	require.True(t, admitted)
	require.NotNil(t, index)
	assert.Equal(t, []string{"accept-language"}, index.VaryOn)
	assert.Len(t, index.Variants, 1)
	assert.True(t, entryIsIndex(index))
	assert.False(t, entryIsResponse(index))

	// A second distinct variant is admitted under the cap.
	index, admitted = admitVariant(options, index, entryFor("sv"), primary)
	require.True(t, admitted)
	assert.Len(t, index.Variants, 2)

	// A third is over the cap: not stored, and the index is left alone.
	_, admitted = admitVariant(options, index, entryFor("de"), primary)
	assert.False(t, admitted, "the cap is what stops one careless Vary filling the cache")

	// One already admitted is republished rather than refused, so the index
	// outlives the variants it points at.
	republished, admitted := admitVariant(options, index, entryFor("en"), primary)
	require.True(t, admitted)
	assert.Len(t, republished.Variants, 2)

	// A resource that changes shape relearns its set from scratch.
	reshaped := entryFor("en")
	reshaped.VaryOn = []string{"accept"}
	reshaped.VariantKey = variantKeyFor(primary, []string{"accept"}, requestVarying("Accept", "text/html"))
	rebuilt, admitted := admitVariant(options, index, reshaped, primary)
	require.True(t, admitted)
	assert.Equal(t, []string{"accept"}, rebuilt.VaryOn)
	assert.Len(t, rebuilt.Variants, 1)

	// A non-varying response replaces the whole resource, index included.
	plain, admitted := admitVariant(options, index, &CacheEntry{StatusCode: http.StatusOK}, primary)
	assert.True(t, admitted)
	assert.Nil(t, plain, "nothing to point at any more")
}

// A variant key has to stay inside the namespace Purge sweeps, and must not add
// a segment -- cache stats reads the service back by splitting on the last colon.
func TestVariantKeyStaysInThePurgeNamespace(t *testing.T) {
	options := CacheOptions{Enabled: true}
	primary := cacheKey("shop", "", requestVarying("Accept-Language", "en"), options)
	variant := variantKeyFor(primary, []string{"accept-language"}, requestVarying("Accept-Language", "en"))

	assert.True(t, len(variant) > len(primary))
	assert.Equal(t, primary, variant[:len(primary)], "a variant lives under its resource's key")
	assert.Equal(t, "shop", serviceFromCacheKey(variant), "and stats still reads the service back")
	assert.NotEqual(t, primary, variant)
}

// Purge has to take the index and every variant with it, or a later lookup finds
// a pointer to bodies that are gone.
func TestCacheVary_PurgeRemovesIndexesAndVariants(t *testing.T) {
	store := testMemoryStore(t)
	middleware := WithCacheMiddleware(CacheConfig{
		Service: "shop",
		Options: CacheOptions{Enabled: true},
		Store:   store,
	}, varyingHandler(nil, "Accept-Language"))

	for _, language := range []string{"en", "sv", "de"} {
		sendCacheRequest(middleware, requestVarying("Accept-Language", language))
	}

	purged, err := store.Purge(t.Context(), "shop", "")
	require.NoError(t, err)
	assert.Equal(t, 4, purged, "three variants and the index that points at them")

	stats := testStats(t, store, CacheStatsOptions{})
	assert.Equal(t, int64(0), stats.Local.Entries, "the store is empty, not merely smaller")
}
