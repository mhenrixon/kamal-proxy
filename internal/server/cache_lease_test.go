package server

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// A lease must not live in the entry namespace. Purge scans "kp:c:<service>:*"
// and, with no path prefix, deletes everything it matches without reading it --
// so a lease parked under that prefix would be silently dropped mid-fetch, and
// counted in the number the CLI prints back to the operator.
func TestCacheLeaseKey_SitsOutsideTheEntryNamespace(t *testing.T) {
	entryKey := cacheKeyPrefix + "shop:abc123"
	leaseKey := cacheLeaseKey(entryKey)

	assert.True(t, strings.HasPrefix(leaseKey, cacheLeaseKeyPrefix))
	assert.False(t, strings.HasPrefix(leaseKey, cacheKeyPrefix),
		"a lease under the entry prefix would be swept by Purge")
	assert.NotEqual(t, entryKey, leaseKey)

	// Distinct entries keep distinct leases.
	assert.NotEqual(t, cacheLeaseKey(cacheKeyPrefix+"shop:one"), cacheLeaseKey(cacheKeyPrefix+"shop:two"))
	assert.Equal(t, leaseKey, cacheLeaseKey(entryKey), "the same entry keys the same lease twice")
}

func TestCacheLeaseOptions_Defaults(t *testing.T) {
	tests := []struct {
		name         string
		options      CacheLeaseOptions
		expectedTTL  time.Duration
		expectedWait time.Duration
	}{
		{
			name:         "zero means the default",
			expectedTTL:  DefaultCacheLeaseTTL,
			expectedWait: DefaultCacheLeaseWait,
		},
		{
			// Negative is how an operator says "off" without the flag's zero
			// value being ambiguous with "unset".
			name:    "negative means off",
			options: CacheLeaseOptions{TTL: -1, Wait: -1},
		},
		{
			name:         "explicit values are kept",
			options:      CacheLeaseOptions{TTL: 7 * time.Second, Wait: 250 * time.Millisecond},
			expectedTTL:  7 * time.Second,
			expectedWait: 250 * time.Millisecond,
		},
		{
			// The wait can be switched off on its own, keeping the free half:
			// the background revalidation still coalesces across the fleet.
			name:         "wait off, ttl on",
			options:      CacheLeaseOptions{Wait: -1},
			expectedTTL:  DefaultCacheLeaseTTL,
			expectedWait: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedTTL, tt.options.ttl())
			assert.Equal(t, tt.expectedWait, tt.options.wait())
		})
	}
}

func TestCacheLease_Predicates(t *testing.T) {
	tests := []struct {
		name          string
		lease         CacheLease
		expectedTaken bool
		expectedMine  bool
	}{
		{
			name:         "acquired",
			lease:        CacheLease{Outcome: CacheLeaseAcquired, Key: "kp:l:shop:x", Token: "abc"},
			expectedMine: true,
		},
		{
			// The only outcome that means back off. Everything else grants, so
			// a store in any doubt costs a duplicate fetch, never a stall.
			name:          "taken",
			lease:         CacheLease{Outcome: CacheLeaseTaken},
			expectedTaken: true,
		},
		{name: "unavailable grants", lease: CacheLease{Outcome: CacheLeaseUnavailable}},
		{name: "deferred grants", lease: CacheLease{Outcome: CacheLeaseDeferred}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedTaken, tt.lease.taken())
			assert.Equal(t, tt.expectedMine, tt.lease.mine())
		})
	}
}

func TestLeaseBreaker_OpensAfterConsecutiveFailuresAndHalfOpens(t *testing.T) {
	now := time.Now()
	breaker := &leaseBreaker{now: func() time.Time { return now }}

	assert.False(t, breaker.open(), "a fresh breaker lets calls through")

	breaker.failed()
	breaker.failed()
	assert.False(t, breaker.open(), "under the threshold it stays closed")

	// A success anywhere in the run resets it: the store is answering again.
	breaker.succeeded()
	breaker.failed()
	breaker.failed()
	assert.False(t, breaker.open())

	breaker.failed()
	assert.True(t, breaker.open(), "three consecutive failures open it")

	// While open, a dead store costs no round trip at all.
	now = now.Add(cacheLeaseBreakerCooldown - time.Millisecond)
	assert.True(t, breaker.open())

	// After the cooldown exactly one call is let through to probe.
	now = now.Add(2 * time.Millisecond)
	assert.False(t, breaker.open(), "the cooldown lets one probe through")

	// If that probe fails it re-opens immediately rather than serving another
	// full run of failures.
	breaker.failed()
	assert.True(t, breaker.open())

	// If it succeeds the breaker closes for good.
	now = now.Add(cacheLeaseBreakerCooldown + time.Millisecond)
	assert.False(t, breaker.open())
	breaker.succeeded()
	assert.False(t, breaker.open())
}

func TestNewLeaseToken_IsUnpredictableAndPresent(t *testing.T) {
	first, ok := newLeaseToken()
	assert.True(t, ok)
	assert.NotEmpty(t, first)

	second, ok := newLeaseToken()
	assert.True(t, ok)
	assert.NotEqual(t, first, second, "a shared token would let one proxy release another's lease")
}
