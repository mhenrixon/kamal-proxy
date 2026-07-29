package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCacheHandler builds a cache in front of a handler, along with a counter of
// how many requests actually reached that handler -- which is the only thing
// that proves a cache did any work.
func testCacheHandler(t *testing.T, options CacheOptions, handler http.HandlerFunc) (*CacheMiddleware, *atomic.Int64) {
	t.Helper()

	options.Normalize()

	var reached atomic.Int64
	counted := func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		handler(w, r)
	}

	store := testMemoryStore(t)
	middleware := WithCacheMiddleware(CacheConfig{
		Service: "shop",
		Options: options,
		Store:   store,
	}, http.HandlerFunc(counted))

	return middleware, &reached
}

func cacheableHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(body))
	}
}

func sendCacheRequest(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func getCached(handler http.Handler, url string) *httptest.ResponseRecorder {
	return sendCacheRequest(handler, httptest.NewRequest(http.MethodGet, url, nil))
}

func TestCacheMiddleware_ServesASecondRequestFromTheStore(t *testing.T) {
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

	first := getCached(middleware, "http://example.com/products")
	assert.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, "hello", first.Body.String())
	assert.Equal(t, cacheStatusMiss, first.Header().Get("X-Cache"))

	second := getCached(middleware, "http://example.com/products")
	assert.Equal(t, http.StatusOK, second.Code)
	assert.Equal(t, "hello", second.Body.String())
	assert.Equal(t, cacheStatusHit, second.Header().Get("X-Cache"))
	assert.Equal(t, "text/plain", second.Header().Get("Content-Type"))
	assert.Equal(t, "5", second.Header().Get("Content-Length"))
	assert.Equal(t, "0", second.Header().Get("Age"))

	assert.Equal(t, int64(1), reached.Load(), "the target should have been asked once")
}

func TestCacheMiddleware_KeysSeparateURLsSeparately(t *testing.T) {
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte(r.URL.RequestURI()))
	})

	assert.Equal(t, "/a", getCached(middleware, "http://example.com/a").Body.String())
	assert.Equal(t, "/b", getCached(middleware, "http://example.com/b").Body.String())
	assert.Equal(t, "/a?x=1", getCached(middleware, "http://example.com/a?x=1").Body.String())
	assert.Equal(t, int64(3), reached.Load())

	assert.Equal(t, cacheStatusHit, getCached(middleware, "http://example.com/a").Header().Get("X-Cache"))
	assert.Equal(t, int64(3), reached.Load())
}

func TestCacheMiddleware_OnlyStoresWhatTheTargetMarkedPublic(t *testing.T) {
	tests := []struct {
		name         string
		options      CacheOptions
		responseCC   string
		setCookie    string
		expectStored bool
	}{
		{name: "public with max-age", responseCC: "public, max-age=60", expectStored: true},
		{name: "public with s-maxage", responseCC: "public, s-maxage=60", expectStored: true},
		{name: "no cache-control at all"},
		{name: "max-age without public", responseCC: "max-age=60"},
		{name: "private", responseCC: "private, max-age=60"},
		{name: "no-store", responseCC: "public, no-store, max-age=60"},
		{name: "public without a lifetime", responseCC: "public"},
		{name: "set-cookie", responseCC: "public, max-age=60", setCookie: "session=abc"},
		{
			name:         "set-cookie with explicit opt-in",
			options:      CacheOptions{AllowSetCookie: true},
			responseCC:   "public, max-age=60",
			setCookie:    "session=abc",
			expectStored: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := tt.options
			options.Enabled = true

			middleware, reached := testCacheHandler(t, options, func(w http.ResponseWriter, r *http.Request) {
				if tt.responseCC != "" {
					w.Header().Set("Cache-Control", tt.responseCC)
				}
				if tt.setCookie != "" {
					w.Header().Set("Set-Cookie", tt.setCookie)
				}
				w.Write([]byte("hello"))
			})

			getCached(middleware, "http://example.com/products")
			second := getCached(middleware, "http://example.com/products")

			assert.Equal(t, "hello", second.Body.String())
			if tt.expectStored {
				assert.Equal(t, int64(1), reached.Load())
				assert.Equal(t, cacheStatusHit, second.Header().Get("X-Cache"))
			} else {
				assert.Equal(t, int64(2), reached.Load())
				assert.Equal(t, cacheStatusMiss, second.Header().Get("X-Cache"))
			}
		})
	}
}

func TestCacheMiddleware_LeavesIneligibleRequestsAlone(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string]string
	}{
		{name: "POST", method: http.MethodPost},
		{name: "authorized", method: http.MethodGet, headers: map[string]string{"Authorization": "Bearer x"}},
		{name: "byte range", method: http.MethodGet, headers: map[string]string{"Range": "bytes=0-1"}},
		{name: "upgrade", method: http.MethodGet, headers: map[string]string{"Upgrade": "websocket"}},
		{name: "request refuses storage", method: http.MethodGet, headers: map[string]string{"Cache-Control": "no-store"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

			for range 2 {
				req := httptest.NewRequest(tt.method, "http://example.com/products", nil)
				for name, value := range tt.headers {
					req.Header.Set(name, value)
				}

				response := sendCacheRequest(middleware, req)
				assert.Equal(t, "hello", response.Body.String())
				assert.Empty(t, response.Header().Get("X-Cache"), "a request the cache never considered should not be labelled")
			}

			assert.Equal(t, int64(2), reached.Load())
		})
	}
}

// A reload refuses the stored copy for itself, but the fresh response it pulls
// still warms the entry for everyone behind it.
func TestCacheMiddleware_RequestNoCacheRefetchesAndRestores(t *testing.T) {
	var served atomic.Int64
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte(fmt.Sprintf("body-%d", served.Add(1))))
	})

	assert.Equal(t, "body-1", getCached(middleware, "http://example.com/products").Body.String())

	reload := httptest.NewRequest(http.MethodGet, "http://example.com/products", nil)
	reload.Header.Set("Cache-Control", "no-cache")
	assert.Equal(t, "body-2", sendCacheRequest(middleware, reload).Body.String())
	assert.Equal(t, int64(2), reached.Load())

	after := getCached(middleware, "http://example.com/products")
	assert.Equal(t, "body-2", after.Body.String())
	assert.Equal(t, cacheStatusHit, after.Header().Get("X-Cache"))
	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_CollapsesConcurrentMissesIntoOneFetch(t *testing.T) {
	const requests = 20

	arrived := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(arrived) })
		<-release

		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte("hello"))
	})

	bodies := make([]string, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Go(func() {
			bodies[i] = getCached(middleware, "http://example.com/products").Body.String()
		})
	}

	<-arrived
	// Give the followers time to queue behind the one request in flight.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, int64(1), reached.Load(), "concurrent misses for one key should cost the target a single request")
	for _, body := range bodies {
		assert.Equal(t, "hello", body)
	}
}

func TestCacheMiddleware_ServesStaleWhileRevalidating(t *testing.T) {
	var served atomic.Int64
	revalidated := make(chan struct{}, 8)

	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		count := served.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=60")
		w.Write([]byte(fmt.Sprintf("body-%d", count)))

		if count > 1 {
			revalidated <- struct{}{}
		}
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	assert.Equal(t, "body-1", getCached(middleware, "http://example.com/products").Body.String())

	// Past the lifetime but inside the stale window.
	now = now.Add(30 * time.Second)

	stale := getCached(middleware, "http://example.com/products")
	assert.Equal(t, "body-1", stale.Body.String(), "the stale copy answers immediately")
	assert.Equal(t, cacheStatusStale, stale.Header().Get("X-Cache"))
	assert.Equal(t, "30", stale.Header().Get("Age"))

	select {
	case <-revalidated:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background revalidation")
	}

	assert.Eventually(t, func() bool {
		return getCached(middleware, "http://example.com/products").Body.String() == "body-2"
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_FiresOneRevalidationForConcurrentStaleHits(t *testing.T) {
	const requests = 20

	var served atomic.Int64
	release := make(chan struct{})

	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) > 1 {
			<-release
		}
		w.Header().Set("Cache-Control", "public, max-age=1, stale-while-revalidate=60")
		w.Write([]byte("hello"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/products")
	now = now.Add(30 * time.Second)

	var wg sync.WaitGroup
	for range requests {
		wg.Go(func() {
			response := getCached(middleware, "http://example.com/products")
			assert.Equal(t, cacheStatusStale, response.Header().Get("X-Cache"))
		})
	}
	wg.Wait()

	// Every stale hit was answered without waiting; only one fetch is behind them.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int64(2), served.Load(), "one background revalidation, not one per stale hit")
	close(release)
}

func TestCacheMiddleware_RefetchesOnceTheStaleWindowHasPassed(t *testing.T) {
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/products")
	now = now.Add(2 * time.Minute)

	response := getCached(middleware, "http://example.com/products")
	assert.Equal(t, cacheStatusMiss, response.Header().Get("X-Cache"))
	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_AnswersHeadFromAStoredGet(t *testing.T) {
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

	getCached(middleware, "http://example.com/products")

	response := sendCacheRequest(middleware, httptest.NewRequest(http.MethodHead, "http://example.com/products", nil))
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, cacheStatusHit, response.Header().Get("X-Cache"))
	assert.Equal(t, "5", response.Header().Get("Content-Length"))
	assert.Empty(t, response.Body.String(), "a HEAD carries the headers of the GET and none of its body")
	assert.Equal(t, int64(1), reached.Load())
}

// A HEAD must never populate the cache: its body is absent by design, and
// storing it would answer later GETs with nothing.
func TestCacheMiddleware_NeverStoresAHeadResponse(t *testing.T) {
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

	sendCacheRequest(middleware, httptest.NewRequest(http.MethodHead, "http://example.com/products", nil))

	response := getCached(middleware, "http://example.com/products")
	assert.Equal(t, "hello", response.Body.String())
	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_PassesOversizedBodiesThroughUnstored(t *testing.T) {
	body := make([]byte, 4096)
	for i := range body {
		body[i] = 'x'
	}

	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true, MaxBodySize: 128}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write(body)
	})

	first := getCached(middleware, "http://example.com/big")
	assert.Len(t, first.Body.Bytes(), 4096, "the client still gets the whole body")

	second := getCached(middleware, "http://example.com/big")
	assert.Len(t, second.Body.Bytes(), 4096)
	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_LeavesEventStreamsStreaming(t *testing.T) {
	flushes := make(chan struct{}, 4)

	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)

		for range 2 {
			w.Write([]byte("data: tick\n\n"))
			w.(http.Flusher).Flush()
			flushes <- struct{}{}
		}
	})

	getCached(middleware, "http://example.com/events")
	assert.Len(t, flushes, 2, "flushes must reach the client rather than being held for the cache")

	getCached(middleware, "http://example.com/events")
	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_PreservesStatusAndHeaders(t *testing.T) {
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"abc"`)
		w.Header().Add("Link", "</a>; rel=preload")
		w.Header().Add("Link", "</b>; rel=preload")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":true}`))
	})

	getCached(middleware, "http://example.com/missing")
	response := getCached(middleware, "http://example.com/missing")

	assert.Equal(t, http.StatusNotFound, response.Code)
	assert.Equal(t, `{"error":true}`, response.Body.String())
	assert.Equal(t, "application/json", response.Header().Get("Content-Type"))
	assert.Equal(t, `"abc"`, response.Header().Get("ETag"))
	assert.Equal(t, []string{"</a>; rel=preload", "</b>; rel=preload"}, response.Header().Values("Link"))
	// Hop-by-hop framing describes the connection it arrived on, not the entry.
	assert.Empty(t, response.Header().Get("Connection"))
}

func TestCacheMiddleware_VaryDimensionsSeparateEntries(t *testing.T) {
	options := CacheOptions{Enabled: true, VaryHeaders: []string{"Accept-Language"}, VaryCookies: []string{"locale"}}

	middleware, reached := testCacheHandler(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "Accept-Language")
		w.Write([]byte(r.Header.Get("Accept-Language") + "/" + r.Header.Get("Cookie")))
	})

	english := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	english.Header.Set("Accept-Language", "en")

	swedish := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	swedish.Header.Set("Accept-Language", "sv")

	assert.Equal(t, "en/", sendCacheRequest(middleware, english).Body.String())
	assert.Equal(t, "sv/", sendCacheRequest(middleware, swedish).Body.String())
	assert.Equal(t, int64(2), reached.Load())

	assert.Equal(t, cacheStatusHit, sendCacheRequest(middleware, english).Header().Get("X-Cache"))
	assert.Equal(t, int64(2), reached.Load())

	// A cookie the key carries separates entries even though the response says
	// nothing about it.
	withCookie := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	withCookie.Header.Set("Accept-Language", "en")
	withCookie.AddCookie(&http.Cookie{Name: "locale", Value: "en-GB"})
	assert.Equal(t, cacheStatusMiss, sendCacheRequest(middleware, withCookie).Header().Get("X-Cache"))
	assert.Equal(t, int64(3), reached.Load())
}

// Varying on a dimension the key does not carry has to mean "do not store",
// never "store one variant and hand it to everybody".
func TestCacheMiddleware_RefusesToStoreAnUnkeyedVary(t *testing.T) {
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "X-Tenant")
		w.Write([]byte(r.Header.Get("X-Tenant")))
	})

	first := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	first.Header.Set("X-Tenant", "acme")
	second := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	second.Header.Set("X-Tenant", "globex")

	assert.Equal(t, "acme", sendCacheRequest(middleware, first).Body.String())
	assert.Equal(t, "globex", sendCacheRequest(middleware, second).Body.String())
	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_VariantSeparatesEntries(t *testing.T) {
	var reached atomic.Int64
	store := testMemoryStore(t)

	middleware := WithCacheMiddleware(CacheConfig{
		Service: "shop",
		Options: CacheOptions{Enabled: true},
		Store:   store,
		Variant: func(r *http.Request) string { return r.Header.Get("X-Variant") },
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte(r.Header.Get("X-Variant")))
	}))

	rollout := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rollout.Header.Set("X-Variant", "rollout")

	assert.Equal(t, "", getCached(middleware, "http://example.com/").Body.String())
	assert.Equal(t, "rollout", sendCacheRequest(middleware, rollout).Body.String())
	assert.Equal(t, int64(2), reached.Load())

	assert.Equal(t, cacheStatusHit, sendCacheRequest(middleware, rollout).Header().Get("X-Cache"))
	assert.Equal(t, int64(2), reached.Load())
}

func TestCacheMiddleware_PassesThroughWithoutAStore(t *testing.T) {
	var reached atomic.Int64
	middleware := WithCacheMiddleware(CacheConfig{
		Service: "shop",
		Options: CacheOptions{Enabled: true},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		cacheableHandler("hello")(w, r)
	}))

	for range 2 {
		assert.Equal(t, "hello", getCached(middleware, "http://example.com/").Body.String())
	}
	assert.Equal(t, int64(2), reached.Load())
}

// The Age a client sees has to count the time the response spent upstream too,
// or a chain of caches would each restart the clock.
func TestCacheMiddleware_CountsUpstreamAge(t *testing.T) {
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("Age", "120")
		w.Write([]byte("hello"))
	})

	now := time.Now()
	middleware.now = func() time.Time { return now }

	getCached(middleware, "http://example.com/products")
	now = now.Add(30 * time.Second)

	response := getCached(middleware, "http://example.com/products")
	assert.Equal(t, cacheStatusHit, response.Header().Get("X-Cache"))

	age, err := strconv.Atoi(response.Header().Get("Age"))
	require.NoError(t, err)
	assert.Equal(t, 150, age)
}
