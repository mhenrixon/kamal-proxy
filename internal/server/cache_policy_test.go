package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseCacheControl(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		expected cacheDirectives
	}{
		{
			name:   "empty",
			values: nil,
		},
		{
			name:     "public with s-maxage",
			values:   []string{"public, s-maxage=60"},
			expected: cacheDirectives{public: true, sMaxAge: time.Minute, hasSMaxAge: true},
		},
		{
			name:     "split across header lines",
			values:   []string{"public", "max-age=30"},
			expected: cacheDirectives{public: true, maxAge: 30 * time.Second, hasMaxAge: true},
		},
		{
			name:     "stale-while-revalidate",
			values:   []string{"public, max-age=1, stale-while-revalidate=59"},
			expected: cacheDirectives{public: true, maxAge: time.Second, hasMaxAge: true, staleWhileRevalidate: 59 * time.Second},
		},
		{
			name:     "no-store and private",
			values:   []string{"no-store, private"},
			expected: cacheDirectives{noStore: true, private: true},
		},
		{
			name:     "case and whitespace insensitive",
			values:   []string{"  PUBLIC ,  S-MaxAge = 10 "},
			expected: cacheDirectives{public: true, sMaxAge: 10 * time.Second, hasSMaxAge: true},
		},
		{
			name:     "quoted value",
			values:   []string{`public, max-age="45"`},
			expected: cacheDirectives{public: true, maxAge: 45 * time.Second, hasMaxAge: true},
		},
		{
			name:   "unparseable delta is ignored rather than treated as zero",
			values: []string{"public, max-age=abc"},
			// A malformed delta must not read as max-age=0: that would silently
			// make the response uncacheable instead of surfacing the typo.
			expected: cacheDirectives{public: true},
		},
		{
			name:     "no-cache and must-revalidate",
			values:   []string{"no-cache, must-revalidate"},
			expected: cacheDirectives{noCache: true, mustRevalidate: true},
		},
		{
			// proxy-revalidate says the same thing to a shared cache, which is
			// the only kind this is.
			name:     "proxy-revalidate",
			values:   []string{"public, max-age=60, proxy-revalidate"},
			expected: cacheDirectives{public: true, maxAge: time.Minute, hasMaxAge: true, mustRevalidate: true},
		},
		{
			name:     "zero max-age is recorded, not dropped",
			values:   []string{"public, max-age=0"},
			expected: cacheDirectives{public: true, hasMaxAge: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseCacheControl(tt.values))
		})
	}
}

func TestRequestMayUseCache(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		headers  map[string]string
		expected bool
	}{
		{name: "plain GET", method: http.MethodGet, expected: true},
		{name: "HEAD", method: http.MethodHead, expected: true},
		{name: "POST", method: http.MethodPost, expected: false},
		{name: "PUT", method: http.MethodPut, expected: false},
		{name: "DELETE", method: http.MethodDelete, expected: false},
		// A shared cache holding one user's authorized response and handing it
		// to the next client is the failure this feature must never have, so
		// the presence of credentials takes the request out of the cache
		// entirely -- stricter than RFC 9111 allows, deliberately.
		{name: "authorized request", method: http.MethodGet, headers: map[string]string{"Authorization": "Bearer x"}, expected: false},
		{name: "range request", method: http.MethodGet, headers: map[string]string{"Range": "bytes=0-99"}, expected: false},
		{name: "upgrade request", method: http.MethodGet, headers: map[string]string{"Upgrade": "websocket"}, expected: false},
		{name: "request says no-store", method: http.MethodGet, headers: map[string]string{"Cache-Control": "no-store"}, expected: false},
		{name: "request says no-cache", method: http.MethodGet, headers: map[string]string{"Cache-Control": "no-cache"}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com/", nil)
			for name, value := range tt.headers {
				req.Header.Set(name, value)
			}

			assert.Equal(t, tt.expected, requestMayUseCache(req))
		})
	}
}

func TestRequestAllowsStoredResponse(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{name: "no directives", expected: true},
		{name: "no-cache", headers: map[string]string{"Cache-Control": "no-cache"}, expected: false},
		{name: "max-age=0", headers: map[string]string{"Cache-Control": "max-age=0"}, expected: false},
		{name: "max-age=60", headers: map[string]string{"Cache-Control": "max-age=60"}, expected: true},
		{name: "legacy pragma", headers: map[string]string{"Pragma": "no-cache"}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			for name, value := range tt.headers {
				req.Header.Set(name, value)
			}

			assert.Equal(t, tt.expected, requestAllowsStoredResponse(req))
		})
	}
}

func TestResponseIsStorable(t *testing.T) {
	enabled := CacheOptions{Enabled: true}

	tests := []struct {
		name             string
		options          CacheOptions
		statusCode       int
		headers          http.Header
		expectedStorable bool
		expectedRefusal  cacheRefusal
		expectedFreshFor time.Duration
		expectedStale    time.Duration
	}{
		{
			name:             "public with s-maxage",
			options:          enabled,
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, s-maxage=60"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			name:             "s-maxage wins over max-age for a shared cache",
			options:          enabled,
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=10, s-maxage=60"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			name:             "stale-while-revalidate window",
			options:          enabled,
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=5, stale-while-revalidate=55"}},
			expectedStorable: true,
			expectedFreshFor: 5 * time.Second,
			expectedStale:    55 * time.Second,
		},
		{
			// The whole belt-and-suspenders rule: freshness alone is not consent.
			name:       "max-age without public",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"max-age=60"}},
		},
		{
			name:       "no cache-control at all",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{},
		},
		{
			name:       "public without a lifetime",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public"}},
		},
		{
			// no-cache permits storing but requires validation before every
			// reuse. This proxy has no way to validate on the way out, so the
			// only honest answer is not to store it at all.
			name:       "public but no-cache",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, no-cache, max-age=60"}},
		},
		{
			// must-revalidate forbids serving stale, so the entry is kept but
			// its stale window is dropped.
			name:             "must-revalidate drops the stale window",
			options:          enabled,
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=5, stale-while-revalidate=55, must-revalidate"}},
			expectedStorable: true,
			expectedFreshFor: 5 * time.Second,
		},
		{
			name:             "proxy-revalidate drops the stale window",
			options:          enabled,
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=5, stale-while-revalidate=55, proxy-revalidate"}},
			expectedStorable: true,
			expectedFreshFor: 5 * time.Second,
		},
		{
			name:       "public but no-store",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, no-store, max-age=60"}},
		},
		{
			name:       "public but private",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, private, max-age=60"}},
		},
		{
			name:       "zero lifetime",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, s-maxage=0"}},
		},
		{
			name:       "set-cookie is refused by default",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}, "Set-Cookie": {"session=abc"}},
		},
		{
			name:             "set-cookie with explicit opt-in",
			options:          CacheOptions{Enabled: true, AllowSetCookie: true},
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=60"}, "Set-Cookie": {"session=abc"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			name:             "max ttl caps a long lifetime",
			options:          CacheOptions{Enabled: true, MaxTTL: 30 * time.Second},
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, s-maxage=3600"}},
			expectedStorable: true,
			expectedFreshFor: 30 * time.Second,
		},
		{
			name:             "permanent redirect",
			options:          enabled,
			statusCode:       http.StatusMovedPermanently,
			headers:          http.Header{"Cache-Control": {"public, max-age=60"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			name:             "not found",
			options:          enabled,
			statusCode:       http.StatusNotFound,
			headers:          http.Header{"Cache-Control": {"public, max-age=60"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			name:       "partial content is never stored",
			options:    enabled,
			statusCode: http.StatusPartialContent,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}},
		},
		{
			name:       "server error",
			options:    enabled,
			statusCode: http.StatusBadGateway,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}},
		},
		{
			name:       "unauthorized",
			options:    enabled,
			statusCode: http.StatusUnauthorized,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}},
		},
		{
			name:       "content-range",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}, "Content-Range": {"bytes 0-99/200"}},
		},
		{
			name:       "event stream",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}, "Content-Type": {"text/event-stream"}},
		},
		{
			// Vary on a dimension the key does not carry would let one client's
			// variant answer another's request, so the response is passed
			// through uncached instead.
			name:       "vary on an unkeyed header",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}, "Vary": {"Accept-Language"}},
		},
		{
			name:             "vary on a keyed header",
			options:          CacheOptions{Enabled: true, VaryHeaders: []string{"accept-language"}},
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=60"}, "Vary": {"Accept-Language"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			// Accounted for outside the key: the entry holds what the target
			// produced, and each client's copy is encoded on its way out.
			name:             "vary on accept-encoding without an encoded body",
			options:          enabled,
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=60"}, "Vary": {"Accept-Encoding"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			// This one really is encoding-specific, and the key does not say
			// which encoding it is.
			name:       "body the target encoded itself",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}, "Content-Encoding": {"gzip"}, "Vary": {"Accept-Encoding"}},
		},
		{
			name:             "body the target encoded, with accept-encoding keyed",
			options:          CacheOptions{Enabled: true, VaryHeaders: []string{"accept-encoding"}},
			statusCode:       http.StatusOK,
			headers:          http.Header{"Cache-Control": {"public, max-age=60"}, "Content-Encoding": {"gzip"}, "Vary": {"Accept-Encoding"}},
			expectedStorable: true,
			expectedFreshFor: time.Minute,
		},
		{
			name:       "vary star",
			options:    enabled,
			statusCode: http.StatusOK,
			headers:    http.Header{"Cache-Control": {"public, max-age=60"}, "Vary": {"*"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := tt.options
			options.Normalize()

			freshFor, stale, refusal := responseIsStorable(options, tt.statusCode, tt.headers)

			assert.Equal(t, tt.expectedStorable, refusal == cacheRefusalNone, "refusal was %q", refusal)
			if tt.expectedRefusal != "" {
				assert.Equal(t, tt.expectedRefusal, refusal)
			}
			if refusal != cacheRefusalNone {
				return
			}
			assert.Equal(t, tt.expectedFreshFor, freshFor)
			assert.Equal(t, tt.expectedStale, stale)
		})
	}
}

func TestCacheKey(t *testing.T) {
	options := CacheOptions{Enabled: true, VaryHeaders: []string{"Accept-Language"}, VaryCookies: []string{"locale"}}
	options.Normalize()

	keyFor := func(configure func(*http.Request)) string {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/products?page=2", nil)
		if configure != nil {
			configure(req)
		}
		return cacheKey("shop", "", req, options)
	}

	base := keyFor(nil)

	assert.Equal(t, base, keyFor(nil), "the same request keys the same way twice")
	assert.True(t, len(base) > 0)

	// Everything that identifies the resource separates entries.
	assert.NotEqual(t, base, cacheKey("other", "", httptest.NewRequest(http.MethodGet, "http://example.com/products?page=2", nil), options))
	assert.NotEqual(t, base, keyFor(func(r *http.Request) { r.URL.Path = "/products/1" }))
	assert.NotEqual(t, base, keyFor(func(r *http.Request) { r.URL.RawQuery = "page=3" }))
	assert.NotEqual(t, base, keyFor(func(r *http.Request) { r.Host = "other.example.com" }))
	assert.NotEqual(t, base, cacheKey("shop", "rollout", httptest.NewRequest(http.MethodGet, "http://example.com/products?page=2", nil), options))

	// Configured dimensions separate entries.
	assert.NotEqual(t, base, keyFor(func(r *http.Request) { r.Header.Set("Accept-Language", "sv") }))
	assert.NotEqual(t, base, keyFor(func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "locale", Value: "sv"}) }))

	// Anything the key does not carry must not change it. Accept-Encoding is
	// among them unless it was named: one entry answers every encoding.
	assert.Equal(t, base, keyFor(func(r *http.Request) { r.Header.Set("Accept-Encoding", "gzip") }))
	assert.Equal(t, base, keyFor(func(r *http.Request) { r.Header.Set("X-Request-Id", "abc") }))
	assert.Equal(t, base, keyFor(func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "session", Value: "abc"}) }))

	// Naming it puts it in the key.
	encodingKeyed := CacheOptions{Enabled: true, VaryHeaders: []string{"Accept-Encoding"}}
	encodingKeyed.Normalize()

	gzipped := httptest.NewRequest(http.MethodGet, "http://example.com/products?page=2", nil)
	gzipped.Header.Set("Accept-Encoding", "gzip")
	assert.NotEqual(t,
		cacheKey("shop", "", httptest.NewRequest(http.MethodGet, "http://example.com/products?page=2", nil), encodingKeyed),
		cacheKey("shop", "", gzipped, encodingKeyed))

	// A HEAD is answered from the GET entry, so it keys identically.
	assert.Equal(t, base, keyFor(func(r *http.Request) { r.Method = http.MethodHead }))

	// The key is namespaced by service so a purge can find its own entries.
	assert.Contains(t, base, "shop")
}
