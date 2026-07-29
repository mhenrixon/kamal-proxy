package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A service sitting at 100% miss used to look identical whether the target never
// marked anything public, the response varied on an unkeyed header, or the body
// was simply too big. Each now names itself.
func TestCacheRefusal_ReportsWhyAResponseWasNotStored(t *testing.T) {
	tests := []struct {
		name     string
		options  CacheOptions
		respond  http.HandlerFunc
		expected cacheRefusal
	}{
		{
			name:     "no cache-control at all",
			respond:  func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello")) },
			expected: cacheRefusalNotPublic,
		},
		{
			name: "fresh but not public",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "max-age=60")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalNotPublic,
		},
		{
			name: "public with no lifetime",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalNoLifetime,
		},
		{
			name: "private",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, private, max-age=60")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalPrivate,
		},
		{
			name: "no-store",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, no-store, max-age=60")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalNoStore,
		},
		{
			name: "no-cache",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, no-cache, max-age=60")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalNoCache,
		},
		{
			name: "set-cookie",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=60")
				w.Header().Set("Set-Cookie", "session=abc")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalSetCookie,
		},
		{
			name: "varies on a header the key does not carry",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=60")
				w.Header().Set("Vary", "X-Tenant")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalVary,
		},
		{
			name: "encoded by the target",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=60")
				w.Header().Set("Content-Encoding", "gzip")
				w.Write([]byte("hello"))
			},
			expected: cacheRefusalContentEncoding,
		},
		{
			name: "event stream",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=60")
				w.Header().Set("Content-Type", "text/event-stream")
				w.Write([]byte("data: x\n\n"))
			},
			expected: cacheRefusalEventStream,
		},
		{
			name: "server error",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=60")
				w.WriteHeader(http.StatusBadGateway)
			},
			expected: cacheRefusalStatus,
		},
		{
			name:    "body over the size limit",
			options: CacheOptions{MaxBodySize: 8},
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=60")
				w.Write(make([]byte, 4096))
			},
			expected: cacheRefusalTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := installFakeTracker(t)

			options := tt.options
			options.Enabled = true
			middleware, _ := testCacheHandler(t, options, tt.respond)

			getCached(middleware, "http://example.com/p")

			assert.Equal(t, 1, tracker.cacheRefusalCount(t.Name(), string(tt.expected)),
				"expected refusal %q; recorded: %v", tt.expected, tracker.cacheRefusalsFor(t.Name()))
		})
	}
}

// A HEAD has no body to store, but if the response was uncacheable anyway that
// is the more useful of the two answers.
func TestCacheRefusal_HeadRequest(t *testing.T) {
	tracker := installFakeTracker(t)
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

	sendCacheRequest(middleware, httptest.NewRequest(http.MethodHead, "http://example.com/p", nil))
	assert.Equal(t, 1, tracker.cacheRefusalCount(t.Name(), string(cacheRefusalHeadRequest)))

	tracker = installFakeTracker(t)
	middleware, _ = testCacheHandler(t, CacheOptions{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})

	sendCacheRequest(middleware, httptest.NewRequest(http.MethodHead, "http://example.com/p", nil))
	assert.Equal(t, 1, tracker.cacheRefusalCount(t.Name(), string(cacheRefusalNotPublic)))
	assert.Equal(t, 0, tracker.cacheRefusalCount(t.Name(), string(cacheRefusalHeadRequest)))
}

// A response that stores cleanly refuses nothing.
func TestCacheRefusal_NothingRecordedForAStorableResponse(t *testing.T) {
	tracker := installFakeTracker(t)
	middleware, _ := testCacheHandler(t, CacheOptions{Enabled: true}, cacheableHandler("hello"))

	getCached(middleware, "http://example.com/p")

	for _, reason := range []cacheRefusal{
		cacheRefusalNotPublic, cacheRefusalNoLifetime, cacheRefusalStatus,
		cacheRefusalVary, cacheRefusalTooLarge, cacheRefusalHeadRequest,
	} {
		assert.Equal(t, 0, tracker.cacheRefusalCount(t.Name(), string(reason)), "reason %q", reason)
	}
}

// Every reason an operator can act on carries the lever that would change it.
func TestCacheRefusal_ActionableReasonsCarryAdvice(t *testing.T) {
	actionable := []cacheRefusal{
		cacheRefusalNotPublic,
		cacheRefusalNoLifetime,
		cacheRefusalSetCookie,
		cacheRefusalVary,
		cacheRefusalContentEncoding,
		cacheRefusalTooLarge,
	}

	for _, reason := range actionable {
		assert.NotEmpty(t, reason.advice(), "reason %q should tell the operator what to do", reason)
	}

	// And the ones nothing can be done about stay quiet rather than inventing
	// advice.
	assert.Empty(t, cacheRefusalEventStream.advice())
	assert.Empty(t, cacheRefusalHijacked.advice())
}

// The refreshed entry restarts its lifetime and re-derives it from the stored
// headers, so a --cache-max-ttl changed since the entry was written takes effect
// on the next refresh.
func TestCacheEntry_Refreshed(t *testing.T) {
	stored := testCacheEntry(time.Minute, 30*time.Second, time.Now().Add(-time.Hour))
	stored.InitialAge = 20 * time.Second
	stored.Header.Set("Cache-Control", "public, max-age=60, stale-while-revalidate=30")

	now := time.Now()
	refreshed := stored.refreshed(CacheOptions{Enabled: true}, now)

	assert.Equal(t, now, refreshed.StoredAt)
	assert.Equal(t, time.Duration(0), refreshed.InitialAge, "a validated entry is not stale on arrival")
	assert.Equal(t, time.Minute, refreshed.FreshFor)
	assert.Equal(t, 30*time.Second, refreshed.StaleWhileRevalidate)
	assert.Equal(t, stored.Body, refreshed.Body, "the body is the whole point of a 304")
	assert.True(t, refreshed.fresh(now))

	// A cap tightened since the entry was written applies at the refresh.
	capped := stored.refreshed(CacheOptions{Enabled: true, MaxTTL: 10 * time.Second}, now)
	assert.Equal(t, 10*time.Second, capped.FreshFor)
}

// The stored copy is left alone if its own headers no longer allow storing --
// the refresh keeps whatever lifetime it had rather than inventing one.
func TestCacheEntry_RefreshedKeepsLifetimeWhenHeadersNoLongerQualify(t *testing.T) {
	stored := testCacheEntry(time.Minute, 0, time.Now())
	stored.Header.Del("Cache-Control")

	refreshed := stored.refreshed(CacheOptions{Enabled: true}, time.Now())

	require.NotNil(t, refreshed)
	assert.Equal(t, time.Minute, refreshed.FreshFor)
}
