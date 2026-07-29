package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staleRevalidatingHandler answers with a short lifetime and a long stale window,
// records how many requests reached it, and reports whether any of them carried a
// conditional header.
func staleRevalidatingHandler(origin *atomic.Int64, conditional *atomic.Bool, body *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)

		// A real target answers a conditional request with 304 and no body,
		// which is exactly what makes an inherited validator so damaging.
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			conditional.Store(true)
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("body"))
		body.Add(1)
	}
}

// The refresh asks whether *the stored entry* is still current, so it carries
// that entry's validator. A client may be holding something older, or nothing at
// all -- its validator answers a different question and must not be inherited.
func TestCacheMiddleware_RevalidationUsesTheStoredValidatorNotTheClients(t *testing.T) {
	var origin atomic.Int64
	seen := make(chan string, 4)

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		if origin.Add(1) > 1 {
			seen <- r.Header.Get("If-None-Match")
		}
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
		w.Header().Set("ETag", `"current"`)
		w.Write([]byte("body"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/p")
	now = now.Add(30 * time.Second)

	// The client is holding a stale validator of its own.
	stale := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	stale.Header.Set("If-None-Match", `"long-gone"`)
	require.Equal(t, cacheStatusStale, sendCacheRequest(middleware, stale).Header().Get("X-Cache"))

	select {
	case validator := <-seen:
		assert.Equal(t, `"current"`, validator, "the refresh should ask about the entry it holds")
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background revalidation")
	}
}

// A 304 means the stored body is still good, so the entry gets a fresh lifetime
// without the body crossing the wire again.
func TestCacheMiddleware_RevalidationRefreshesFromA304WithoutABody(t *testing.T) {
	var origin, bodies atomic.Int64
	var conditional atomic.Bool

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true},
		staleRevalidatingHandler(&origin, &conditional, &bodies))

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/p")
	require.Equal(t, int64(1), origin.Load())

	now = now.Add(30 * time.Second)
	require.Equal(t, cacheStatusStale, getCached(middleware, "http://example.com/p").Header().Get("X-Cache"))

	// Polling costs no upstream requests: a revalidation is already in flight,
	// so a stale hit joins it rather than starting another.
	require.Eventually(t, func() bool {
		return getCached(middleware, "http://example.com/p").Header().Get("X-Cache") == cacheStatusHit
	}, 2*time.Second, 10*time.Millisecond, "the 304 should have refreshed the entry")

	assert.True(t, conditional.Load(), "the refresh asked conditionally")
	assert.Equal(t, int64(1), bodies.Load(), "and the body was never sent a second time")
	assert.Equal(t, int64(2), origin.Load(), "one warm-up and one revalidation, not one fetch per stale hit")

	// The refreshed entry still serves the original body.
	assert.Equal(t, "body", getCached(middleware, "http://example.com/p").Body.String())
}

// When the target says the resource changed, the new body replaces the entry.
func TestCacheMiddleware_RevalidationTakesAChangedBody(t *testing.T) {
	var origin atomic.Int64

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		count := origin.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
		w.Header().Set("ETag", `"v`+strconv.FormatInt(count, 10)+`"`)
		fmt.Fprintf(w, "body-%d", count)
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	require.Equal(t, "body-1", getCached(middleware, "http://example.com/p").Body.String())
	now = now.Add(30 * time.Second)

	require.Equal(t, "body-1", getCached(middleware, "http://example.com/p").Body.String(), "the stale copy answers first")

	assert.Eventually(t, func() bool {
		return getCached(middleware, "http://example.com/p").Body.String() == "body-2"
	}, 2*time.Second, 10*time.Millisecond)
}

// An entry the target gave no validator for is refreshed by a plain fetch --
// there is nothing to ask about.
func TestCacheMiddleware_RevalidationIsUnconditionalWithoutAValidator(t *testing.T) {
	var origin atomic.Int64
	seen := make(chan http.Header, 4)

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		if origin.Add(1) > 1 {
			seen <- r.Header.Clone()
		}
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
		w.Write([]byte("body"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/p")
	now = now.Add(30 * time.Second)
	getCached(middleware, "http://example.com/p")

	select {
	case header := <-seen:
		assert.Empty(t, header.Get("If-None-Match"))
		assert.Empty(t, header.Get("If-Modified-Since"))
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background revalidation")
	}
}

// Last-Modified stands in when the target offers no ETag.
func TestCacheMiddleware_RevalidationFallsBackToLastModified(t *testing.T) {
	var origin atomic.Int64
	seen := make(chan http.Header, 4)
	lastModified := time.Now().UTC().Add(-time.Hour).Format(http.TimeFormat)

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		if origin.Add(1) > 1 {
			seen <- r.Header.Clone()
		}
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
		w.Header().Set("Last-Modified", lastModified)
		w.Write([]byte("body"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/p")
	now = now.Add(30 * time.Second)
	getCached(middleware, "http://example.com/p")

	select {
	case header := <-seen:
		assert.Equal(t, lastModified, header.Get("If-Modified-Since"))
		assert.Empty(t, header.Get("If-None-Match"), "one validator, not both")
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background revalidation")
	}
}

// The same holds for the other precondition headers, which would each turn the
// revalidation into something other than a plain fetch.
func TestCacheMiddleware_RevalidationStripsEveryPrecondition(t *testing.T) {
	preconditions := []string{"If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range"}

	seen := make(chan http.Header, 4)
	var origin atomic.Int64

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		if origin.Add(1) > 1 {
			seen <- r.Header.Clone()
		}
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=600")
		w.Write([]byte("body"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/p")
	now = now.Add(30 * time.Second)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	for _, name := range preconditions {
		req.Header.Set(name, "x")
	}
	// Range never reaches the cache at all, but a precondition alongside it
	// would, so pin the whole set.
	sendCacheRequest(middleware, req)

	select {
	case header := <-seen:
		for _, name := range preconditions {
			assert.Empty(t, header.Get(name), "%s should have been stripped from the revalidation", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background revalidation")
	}
}

// must-revalidate forbids answering from a stale entry, so the stale window is
// dropped at store time and the next request past the lifetime is a real fetch.
func TestCacheMiddleware_MustRevalidateNeverServesStale(t *testing.T) {
	var origin atomic.Int64

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=5, stale-while-revalidate=600, must-revalidate")
		w.Write([]byte("body"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	require.Equal(t, cacheStatusMiss, getCached(middleware, "http://example.com/p").Header().Get("X-Cache"))
	assert.Equal(t, cacheStatusHit, getCached(middleware, "http://example.com/p").Header().Get("X-Cache"))

	now = now.Add(30 * time.Second)

	response := getCached(middleware, "http://example.com/p")
	assert.Equal(t, cacheStatusMiss, response.Header().Get("X-Cache"), "a must-revalidate entry may not be served stale")
	assert.Equal(t, int64(2), origin.Load())
}

// A response marked no-cache has to be validated before every reuse. This proxy
// has no way to validate on the way out, so it declines to store it rather than
// serve it unvalidated.
func TestCacheMiddleware_ResponseNoCacheIsNotStored(t *testing.T) {
	var origin atomic.Int64

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		origin.Add(1)
		w.Header().Set("Cache-Control", "public, no-cache, max-age=60")
		w.Write([]byte("body"))
	})

	for range 2 {
		response := getCached(middleware, "http://example.com/p")
		assert.Equal(t, cacheStatusMiss, response.Header().Get("X-Cache"))
	}

	assert.Equal(t, int64(2), origin.Load())
}

// A conditional request against a cold cache is answered by the target, not by
// the proxy, and stores nothing -- the client already holds the body, so there
// is nothing for the cache to keep.
func TestCacheMiddleware_ConditionalRequestOnAColdCacheIsPassedThrough(t *testing.T) {
	var origin, bodies atomic.Int64
	var conditional atomic.Bool

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true},
		staleRevalidatingHandler(&origin, &conditional, &bodies))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	req.Header.Set("If-None-Match", `"v1"`)

	response := sendCacheRequest(middleware, req)
	assert.Equal(t, http.StatusNotModified, response.Code)
	assert.True(t, conditional.Load(), "the client's own request keeps its validator")
	assert.Equal(t, int64(1), origin.Load())
}
