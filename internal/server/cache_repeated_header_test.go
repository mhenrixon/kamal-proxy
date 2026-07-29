package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client may send a header as several field lines rather than one
// comma-separated value; RFC 9110 section 5.3 says they mean the same thing.
// Keying on only the first made two genuinely different requests collide on one
// entry -- a client asking for JSON could be handed the HTML another client's
// request had stored.
func TestCacheKey_RepeatedHeaderValuesAllEnterTheKey(t *testing.T) {
	options := CacheOptions{Enabled: true, VaryHeaders: []string{"Accept"}}
	options.Normalize()

	keyFor := func(values ...string) string {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
		for _, value := range values {
			req.Header.Add("Accept", value)
		}
		return cacheKey("shop", "", req, options)
	}

	single := keyFor("text/html")

	assert.NotEqual(t, single, keyFor("text/html", "application/json"),
		"a second field line changes what the client accepts, so it must change the key")
	assert.NotEqual(t, keyFor("application/json"), keyFor("text/html", "application/json"))

	// Order is part of the value, as it is for a single comma-separated line.
	assert.NotEqual(t, keyFor("text/html", "application/json"), keyFor("application/json", "text/html"))

	// The two spellings of one capability agree, which is what makes joining
	// the right reduction rather than hashing the slice.
	joined := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	joined.Header.Set("Accept", "text/html, application/json")
	assert.Equal(t, keyFor("text/html", "application/json"), cacheKey("shop", "", joined, options))
}

// The same applies to the encoding guard: a client offering gzip on a second
// field line still accepts gzip.
func TestClientAcceptsEncoding_ReadsEveryFieldLine(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	req.Header.Add("Accept-Encoding", "deflate")
	req.Header.Add("Accept-Encoding", "gzip")

	assert.True(t, clientAcceptsEncoding(req, "gzip"), "the second field line offers gzip")
	assert.True(t, clientAcceptsEncoding(req, "deflate"))
	assert.False(t, clientAcceptsEncoding(req, "br"))

	// And a refusal on a later line is still a refusal.
	refusing := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	refusing.Header.Add("Accept-Encoding", "gzip")
	refusing.Header.Add("Accept-Encoding", "br;q=0")
	assert.False(t, refusing.Header == nil)
	assert.False(t, clientAcceptsEncoding(refusing, "br"))
}

func TestNormalizeAcceptEncoding_ReadsEveryFieldLine(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	req.Header.Add("Accept-Encoding", "gzip")
	req.Header.Add("Accept-Encoding", "br")

	assert.Equal(t, "br,gzip,identity", keyValueFor(req, acceptEncodingHeader))
}

// #78 gave the fleet one fetch per rollover, but the node that waited on
// another proxy's lease told its own followers nothing -- so every local
// follower went to the origin anyway. One waiter served, nineteen fetches.
func TestCacheLease_WaiterPublishesToItsOwnFollowers(t *testing.T) {
	const followers = 12

	server := miniredis.RunT(t)

	var origin atomic.Int64
	newNode := func() *CacheMiddleware {
		store, err := NewCacheStore(CacheStoreConfig{URL: "redis://" + server.Addr()})
		require.NoError(t, err)
		t.Cleanup(func() { store.Close() })

		return WithCacheMiddleware(CacheConfig{
			Service: t.Name(),
			Options: CacheOptions{Enabled: true},
			Store:   store,
			Leases:  CacheLeaseOptions{},
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin.Add(1)
			time.Sleep(40 * time.Millisecond)
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Write([]byte("hello"))
		}))
	}

	holder, waiter := newNode(), newNode()

	// The holder takes the lease and starts fetching.
	var holding sync.WaitGroup
	holding.Go(func() { getCached(holder, "http://example.com/p") })
	time.Sleep(15 * time.Millisecond)

	// The waiting node gets a burst: one becomes its leader and waits on the
	// lease, the rest queue behind it locally.
	var burst sync.WaitGroup
	bodies := make([]string, followers)
	for i := range followers {
		burst.Go(func() {
			bodies[i] = getCached(waiter, "http://example.com/p").Body.String()
		})
		time.Sleep(time.Millisecond)
	}

	burst.Wait()
	holding.Wait()

	for _, body := range bodies {
		assert.Equal(t, "hello", body)
	}
	assert.Equal(t, int64(1), origin.Load(),
		"the waiting node must hand what it was given to its own followers, not send them all to the origin")
}
