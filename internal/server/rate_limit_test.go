package server

import (
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

// testRateLimiter builds a limiter driven by a clock the test controls, so that
// refill and eviction are asserted on exactly rather than slept for.
func testRateLimiter(t *testing.T, limit float64, burst int, exempt []string) (*rateLimiter, *time.Time) {
	t.Helper()

	clock := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	limiter, err := newRateLimiter(limit, burst, exempt, nil, "")
	require.NoError(t, err)

	limiter.now = func() time.Time { return clock }
	limiter.lastSweep = clock

	return limiter, &clock
}

func testRateLimitRequest(peer string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = peer

	return req
}

func TestRateLimiter_AllowsUpToBurstThenRejects(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 3, nil)
	req := testRateLimitRequest("203.0.113.5:44321")

	for i := range 3 {
		assert.True(t, limiter.allow(req), "request %d should be within the burst", i+1)
	}

	assert.False(t, limiter.allow(req), "the request after the burst should be rejected")
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	limiter, clock := testRateLimiter(t, 2, 2, nil)
	req := testRateLimitRequest("203.0.113.5:44321")

	require.True(t, limiter.allow(req))
	require.True(t, limiter.allow(req))
	require.False(t, limiter.allow(req))

	// One token per half second at 2/s.
	*clock = clock.Add(500 * time.Millisecond)

	assert.True(t, limiter.allow(req), "a token should have been restored")
	assert.False(t, limiter.allow(req), "only one token should have been restored")
}

func TestRateLimiter_SeparatesClients(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 1, nil)

	require.True(t, limiter.allow(testRateLimitRequest("203.0.113.5:44321")))
	require.False(t, limiter.allow(testRateLimitRequest("203.0.113.5:44321")))

	assert.True(t, limiter.allow(testRateLimitRequest("203.0.113.6:44321")),
		"one client exhausting its budget must not spend another's")
}

// A /128 key would be decorative: every IPv6 client holds at least a /64 and
// can rotate the low bits per request, escaping the limit while allocating a
// bucket each time.
func TestRateLimiter_GroupsIPv6ClientsByPrefix(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 2, nil)

	require.True(t, limiter.allow(testRateLimitRequest("[2001:db8::1]:44321")))
	require.True(t, limiter.allow(testRateLimitRequest("[2001:db8::9999]:44321")))

	assert.False(t, limiter.allow(testRateLimitRequest("[2001:db8::dead:beef]:44321")),
		"rotating within a /64 must not escape the limit")

	assert.True(t, limiter.allow(testRateLimitRequest("[2001:db8:0:1::1]:44321")),
		"a different /64 is a different client")
}

func TestRateLimiter_SeparatesIPv4Addresses(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 1, nil)

	require.True(t, limiter.allow(testRateLimitRequest("203.0.113.1:44321")))

	assert.True(t, limiter.allow(testRateLimitRequest("203.0.113.2:44321")),
		"IPv4 is keyed on the full address, so neighbours are separate clients")
}

// An IPv4-mapped IPv6 peer must land in the same bucket as the plain IPv4 one,
// or connecting over IPv6 doubles the budget.
func TestRateLimiter_NormalizesMappedAddresses(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 1, nil)

	require.True(t, limiter.allow(testRateLimitRequest("203.0.113.5:44321")))

	assert.False(t, limiter.allow(testRateLimitRequest("[::ffff:203.0.113.5]:44321")),
		"the mapped form of an address is the same client")
}

func TestRateLimiter_ExemptsListedRanges(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 1, []string{"10.0.0.0/8"})
	req := testRateLimitRequest("10.1.2.3:44321")

	for i := range 20 {
		assert.True(t, limiter.allow(req), "exempt request %d should never be limited", i+1)
	}

	assert.Zero(t, limiter.tracked(), "an exempt client should not occupy a bucket")
}

// A malformed forwarded chain must not become an escape hatch, and must not be
// able to allocate a bucket per request either.
func TestRateLimiter_KeysUnresolvableClientsToOneBucket(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 2, nil)

	require.True(t, limiter.allow(testRateLimitRequest("not-an-address")))
	require.True(t, limiter.allow(testRateLimitRequest("@")))

	assert.False(t, limiter.allow(testRateLimitRequest("also-not-an-address")),
		"clients we cannot identify share one bounded budget")
	assert.Zero(t, limiter.tracked(), "the shared bucket is not a tracked client")
}

func TestRateLimiter_EvictsIdleBuckets(t *testing.T) {
	limiter, clock := testRateLimiter(t, 1, 1, nil)

	require.True(t, limiter.allow(testRateLimitRequest("203.0.113.5:44321")))
	require.Equal(t, 1, limiter.tracked())

	// Long enough for the bucket to refill completely and for a sweep to be due.
	*clock = clock.Add(rateLimitSweepInterval + time.Second)
	limiter.allow(testRateLimitRequest("203.0.113.99:44321"))

	assert.Equal(t, 1, limiter.tracked(),
		"a fully replenished bucket carries no state, so forgetting it is free")
}

func TestRateLimiter_DoesNotEvictBucketsInDebt(t *testing.T) {
	limiter, clock := testRateLimiter(t, 0.01, 1, nil)
	spender := testRateLimitRequest("203.0.113.5:44321")

	require.True(t, limiter.allow(spender))
	require.False(t, limiter.allow(spender))

	// A sweep falls due, but at 0.01/s the bucket is nowhere near refilled.
	*clock = clock.Add(rateLimitSweepInterval + time.Second)
	limiter.allow(testRateLimitRequest("203.0.113.99:44321"))

	assert.False(t, limiter.allow(spender),
		"eviction must not hand back a budget the client has already spent")
}

// Past the tracking cap new clients share the overflow bucket. Leaving them
// untracked would mean unlimited, which is the escape this feature exists to
// close.
func TestRateLimiter_OverflowsAtTrackingCap(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 1, nil)

	for i := range rateLimitMaxTrackedClients {
		peer := fmt.Sprintf("10.%d.%d.%d:44321", i>>16&0xff, i>>8&0xff, i&0xff)
		require.True(t, limiter.allow(testRateLimitRequest(peer)))
	}
	require.Equal(t, rateLimitMaxTrackedClients, limiter.tracked())

	require.True(t, limiter.allow(testRateLimitRequest("203.0.113.5:44321")))

	assert.False(t, limiter.allow(testRateLimitRequest("203.0.113.6:44321")),
		"clients past the cap share the overflow budget rather than escaping it")
	assert.Equal(t, rateLimitMaxTrackedClients, limiter.tracked(),
		"the cap must actually bound the map")
}

func TestRateLimiter_ResolvesClientThroughTrustedProxy(t *testing.T) {
	limiter, err := newRateLimiter(1, 1, nil, []string{"10.0.0.0/8"}, "")
	require.NoError(t, err)

	first := testRateLimitRequest("10.0.0.1:44321")
	first.Header.Set("X-Forwarded-For", "203.0.113.5")

	second := testRateLimitRequest("10.0.0.1:44321")
	second.Header.Set("X-Forwarded-For", "203.0.113.6")

	require.True(t, limiter.allow(first))
	require.False(t, limiter.allow(first))

	assert.True(t, limiter.allow(second),
		"behind a proxy every client must get its own budget, not one shared bucket")
}

// Without a declared proxy, a header is just something the client wrote.
func TestRateLimiter_IgnoresForwardedHeaderWithoutTrustedProxy(t *testing.T) {
	limiter, _ := testRateLimiter(t, 1, 1, nil)

	first := testRateLimitRequest("203.0.113.5:44321")
	first.Header.Set("X-Forwarded-For", "198.51.100.1")

	second := testRateLimitRequest("203.0.113.5:44321")
	second.Header.Set("X-Forwarded-For", "198.51.100.2")

	require.True(t, limiter.allow(first))

	assert.False(t, limiter.allow(second),
		"rotating a forged header must not buy a fresh budget")
}

func TestRateLimiter_RetryAfterSeconds(t *testing.T) {
	tests := []struct {
		limit    float64
		expected int
	}{
		{100, 1},
		{1, 1},
		{0.5, 2},
		{0.1, 10},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v per second", tt.limit), func(t *testing.T) {
			limiter, _ := testRateLimiter(t, tt.limit, 1, nil)

			assert.Equal(t, tt.expected, limiter.retryAfterSeconds())
		})
	}
}

func TestNewRateLimiter_RejectsInvalidExemptRanges(t *testing.T) {
	_, err := newRateLimiter(1, 1, []string{"not-a-range"}, nil, "")

	assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
}

// The limiter is reached from every request goroutine at once, so the budget
// has to hold exactly under contention rather than merely be race-free.
func TestRateLimiter_DoesNotOverspendUnderConcurrency(t *testing.T) {
	const burst = 50

	limiter, _ := testRateLimiter(t, 1, burst, nil)

	var allowed atomic.Int64
	var wg sync.WaitGroup

	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.allow(testRateLimitRequest("203.0.113.5:44321")) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.EqualValues(t, burst, allowed.Load(),
		"concurrent requests must not spend the same token twice")
}

func BenchmarkRateLimiter_Allows(b *testing.B) {
	limiter, err := newRateLimiter(1e9, 1e9, nil, nil, "")
	require.NoError(b, err)

	req := testRateLimitRequest("203.0.113.5:44321")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		limiter.allow(req)
	}
}
