package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The raw header is unusable as a key dimension: every browser and version
// sends its own ordering, spacing and q values for the same set of encodings.
// Keying on it splits one resource across a dozen entries; keying on what the
// client will actually accept collapses them back.
func TestNormalizeAcceptEncoding(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{name: "absent means identity only", expected: "identity"},
		{name: "single encoding", header: "gzip", expected: "gzip,identity"},
		{
			// The whole point: these are the same client capability written
			// three ways, and they must key alike.
			name:     "order does not matter",
			header:   "gzip, deflate, br",
			expected: "br,deflate,gzip,identity",
		},
		{name: "reordered", header: "br, gzip, deflate", expected: "br,deflate,gzip,identity"},
		{name: "spacing and case", header: "  GZIP ,Deflate,   BR ", expected: "br,deflate,gzip,identity"},
		{
			name:     "q values do not change what is accepted",
			header:   "gzip;q=0.8, br;q=1.0, deflate;q=0.5",
			expected: "br,deflate,gzip,identity",
		},
		{
			// q=0 is a refusal, and refusing an encoding really does change
			// which entries this client may be served.
			name:     "q=0 is a refusal",
			header:   "gzip, br;q=0",
			expected: "gzip,identity",
		},
		{
			name:     "encodings the proxy does not know are dropped",
			header:   "gzip, exi, sdch, pack200-gzip",
			expected: "gzip,identity",
		},
		{
			name:     "a wildcard accepts everything",
			header:   "*",
			expected: "br,deflate,gzip,identity,zstd",
		},
		{
			name:     "a wildcard with an explicit refusal",
			header:   "*, br;q=0",
			expected: "deflate,gzip,identity,zstd",
		},
		{name: "wildcard refusing everything still allows identity", header: "*;q=0", expected: "identity"},
		{
			// Identity is implicitly acceptable unless explicitly refused.
			name:     "identity refused outright",
			header:   "gzip, identity;q=0",
			expected: "gzip",
		},
		{name: "zstd", header: "zstd, gzip", expected: "gzip,identity,zstd"},
		{name: "malformed q is read as accepted", header: "gzip;q=banana", expected: "gzip,identity"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeAcceptEncoding(tt.header))
		})
	}
}

// Naming accept-encoding in --cache-vary-header must give a usable number of
// entries, not one per header string in the wild.
func TestCacheKey_NormalizesAcceptEncoding(t *testing.T) {
	options := CacheOptions{Enabled: true, VaryHeaders: []string{"Accept-Encoding"}}
	options.Normalize()

	keyFor := func(acceptEncoding string) string {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}
		return cacheKey("shop", "", req, options)
	}

	// Every one of these is the same client capability.
	chrome := keyFor("gzip, deflate, br, zstd")
	assert.Equal(t, chrome, keyFor("br, deflate, gzip, zstd"))
	assert.Equal(t, chrome, keyFor("gzip;q=1.0, deflate;q=0.8, br;q=0.9, zstd"))
	assert.Equal(t, chrome, keyFor("  GZIP, DEFLATE , BR,zstd "))
	assert.Equal(t, chrome, keyFor("gzip, deflate, br, zstd, exi"))

	// A client that genuinely accepts less gets its own entry, because it
	// genuinely cannot be served the same bytes.
	assert.NotEqual(t, chrome, keyFor("gzip"))
	assert.NotEqual(t, chrome, keyFor(""))
	assert.NotEqual(t, chrome, keyFor("gzip, deflate, br, zstd, identity;q=0"))
}

// Without the flag, one entry still serves every client -- the cache stores what
// the target produced and --compress encodes it per client.
func TestCacheKey_LeavesAcceptEncodingOutByDefault(t *testing.T) {
	options := CacheOptions{Enabled: true}

	keyFor := func(acceptEncoding string) string {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
		req.Header.Set("Accept-Encoding", acceptEncoding)
		return cacheKey("shop", "", req, options)
	}

	assert.Equal(t, keyFor("gzip, br"), keyFor(""))
}

func TestClientAcceptsEncoding(t *testing.T) {
	tests := []struct {
		name            string
		acceptEncoding  string
		contentEncoding string
		expected        bool
	}{
		{name: "an unencoded entry suits everyone", contentEncoding: "", expected: true},
		{name: "identity suits everyone", contentEncoding: "identity", expected: true},
		{name: "gzip to a gzip client", acceptEncoding: "gzip, br", contentEncoding: "gzip", expected: true},
		{name: "gzip to a client that asked for none", acceptEncoding: "", contentEncoding: "gzip"},
		{name: "br to a gzip-only client", acceptEncoding: "gzip", contentEncoding: "br"},
		{name: "gzip to a wildcard client", acceptEncoding: "*", contentEncoding: "gzip", expected: true},
		{name: "an encoding the client refused", acceptEncoding: "gzip, br;q=0", contentEncoding: "br"},
		{name: "case insensitive", acceptEncoding: "GZIP", contentEncoding: "gzip", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}

			assert.Equal(t, tt.expected, clientAcceptsEncoding(req, tt.contentEncoding))
		})
	}
}

// The guard is belt and braces: it protects entries written before the key
// carried an encoding dimension, and entries left behind when the flag is turned
// off. Serving bytes a client cannot decode is the one outcome that must not
// happen.
func TestCacheMiddleware_NeverServesAnEncodingTheClientCannotRead(t *testing.T) {
	middleware, reached := testCacheHandler(t, CacheOptions{Enabled: true, VaryHeaders: []string{"accept-encoding"}},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")
			w.Write([]byte("compressed-bytes"))
		})

	warm := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	warm.Header.Set("Accept-Encoding", "gzip")
	require.Equal(t, cacheStatusMiss, sendCacheRequest(middleware, warm).Header().Get("X-Cache"))

	// Same capability, different spelling: served from the entry.
	again := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	again.Header.Set("Accept-Encoding", "GZIP;q=1.0")
	assert.Equal(t, cacheStatusHit, sendCacheRequest(middleware, again).Header().Get("X-Cache"))
	assert.Equal(t, int64(1), reached.Load())
}

// A target that encodes its own responses is cacheable once the operator says
// the key should carry the encoding.
func TestCacheMiddleware_StoresTargetEncodedResponsesWhenEncodingIsKeyed(t *testing.T) {
	options := CacheOptions{Enabled: true, VaryHeaders: []string{"accept-encoding"}}

	middleware, reached := testCacheHandler(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Write([]byte("compressed-bytes"))
	})

	gzipped := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		return req
	}

	assert.Equal(t, cacheStatusMiss, sendCacheRequest(middleware, gzipped()).Header().Get("X-Cache"))
	assert.Equal(t, cacheStatusHit, sendCacheRequest(middleware, gzipped()).Header().Get("X-Cache"))
	assert.Equal(t, int64(1), reached.Load())

	// A client that cannot read gzip is never handed those bytes.
	plain := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	response := sendCacheRequest(middleware, plain)
	assert.Equal(t, cacheStatusMiss, response.Header().Get("X-Cache"))
	assert.Equal(t, int64(2), reached.Load())
}
