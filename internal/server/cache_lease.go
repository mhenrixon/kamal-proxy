package server

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// A lease is how one proxy tells the rest of a fleet "I am fetching this key,
// you need not". The in-process inflightGroup already elects one leader per node
// per key; the lease is the same idea one level up, and only that leader ever
// touches it -- so lease traffic is one operation per node per key, not one per
// request.
//
// Every outcome except CacheLeaseTaken means "you fetch". A store that is
// unreachable, slow, or in any doubt grants, because granting on doubt costs the
// duplicate fetch the lease was avoiding, while withholding on doubt costs an
// origin outage.

const (
	// cacheLeaseKeyPrefix namespaces leases away from entries. It has to sit
	// outside cacheKeyPrefix: Purge scans "kp:c:<service>:*" and, with no path
	// prefix, deletes everything it matches without reading it -- so a lease
	// parked under the entry prefix would be silently swept mid-fetch and
	// counted in the number the CLI prints back.
	cacheLeaseKeyPrefix = "kp:l:"

	// cacheLeasePollInterval is how often a waiting proxy asks whether the
	// holder has published yet. It is only affordable because the local single
	// flight caps waiters at one per node per key -- see the note on
	// cacheLeaseWaiter.
	cacheLeasePollInterval = 25 * time.Millisecond

	// cacheLeaseBreakerThreshold is how many consecutive failures mean the store
	// is not worth asking again for a while.
	cacheLeaseBreakerThreshold = 3

	// cacheLeaseBreakerCooldown is how long the breaker stays open. A dead Redis
	// then costs one probe per cooldown per node, rather than a timeout on every
	// miss.
	cacheLeaseBreakerCooldown = 5 * time.Second
)

// CacheLeaseOptions configures the cross-node single flight. A zero value takes
// the defaults; a negative value switches the piece off.
type CacheLeaseOptions struct {
	// TTL bounds how long one proxy's claim outlives the proxy itself. A holder
	// releases as soon as it knows the outcome, so this only matters when a node
	// is killed mid-fetch -- and then the cost is a duplicate fetch. Negative
	// disables leasing entirely.
	TTL time.Duration
	// Wait is how long a proxy on a cold miss waits for another proxy's fetch to
	// land before going to the target itself. Separate from TTL on purpose: the
	// TTL wants to outlive a slow origin, the wait wants to be shorter than one.
	// Negative or zero keeps the free half -- background revalidations still
	// coalesce across the fleet, since nobody waits on those.
	Wait time.Duration
}

func (o CacheLeaseOptions) ttl() time.Duration {
	if o.TTL < 0 {
		return 0
	}
	if o.TTL == 0 {
		return DefaultCacheLeaseTTL
	}
	return o.TTL
}

func (o CacheLeaseOptions) wait() time.Duration {
	if o.Wait < 0 {
		return 0
	}
	if o.Wait == 0 {
		return DefaultCacheLeaseWait
	}
	return o.Wait
}

// Enabled reports whether leasing should be attempted at all.
func (o CacheLeaseOptions) Enabled() bool {
	return o.ttl() > 0
}

type CacheLeaseOutcome string

const (
	// CacheLeaseAcquired: this proxy fetches, and must release when done.
	CacheLeaseAcquired CacheLeaseOutcome = "acquired"
	// CacheLeaseTaken: another proxy is already fetching. The only outcome that
	// means back off.
	CacheLeaseTaken CacheLeaseOutcome = "taken"
	// CacheLeaseUnavailable: the store could not answer, so this proxy fetches.
	CacheLeaseUnavailable CacheLeaseOutcome = "unavailable"
	// CacheLeaseDeferred: the store has been failing, so it was not asked at
	// all. Distinct from unavailable so a dashboard can tell "Redis is sick"
	// from "we stopped asking".
	CacheLeaseDeferred CacheLeaseOutcome = "deferred"
)

// CacheLease is one acquisition attempt. Token identifies this attempt so that
// releasing cannot drop a lease that expired and was claimed by someone else.
type CacheLease struct {
	Outcome CacheLeaseOutcome
	Key     string
	Token   string
}

// taken reports whether another proxy holds the fetch.
func (l CacheLease) taken() bool {
	return l.Outcome == CacheLeaseTaken
}

// mine reports whether this proxy holds a lease it must release.
func (l CacheLease) mine() bool {
	return l.Outcome == CacheLeaseAcquired && l.Key != "" && l.Token != ""
}

// cacheLeaseKey is where the lease for an entry key lives.
func cacheLeaseKey(entryKey string) string {
	return cacheLeaseKeyPrefix + strings.TrimPrefix(entryKey, cacheKeyPrefix)
}

// newLeaseToken returns an unguessable identifier for one acquisition. A shared
// or predictable token would let one proxy release another's lease, handing a
// third the fetch the lease exists to prevent. Failing to read randomness
// reports false, and the caller then grants without leasing rather than
// pretending to hold something.
func newLeaseToken() (string, bool) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return "", false
	}

	return hex.EncodeToString(token), true
}

// leaseBreaker stops a store that has gone quiet from costing a timeout on every
// request. After a run of consecutive failures it reports open, and callers skip
// the round trip entirely and grant; after a cooldown it lets exactly one call
// through to find out whether the store came back.
type leaseBreaker struct {
	lock     sync.Mutex
	failures int
	openedAt time.Time

	// now is a seam for tests; nothing else replaces it.
	now func() time.Time
}

func (b *leaseBreaker) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// open reports whether the store should be skipped. Calling it consumes the
// half-open probe, so it must be called once per attempt.
func (b *leaseBreaker) open() bool {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.failures < cacheLeaseBreakerThreshold {
		return false
	}

	if b.clock().Sub(b.openedAt) < cacheLeaseBreakerCooldown {
		return true
	}

	// Half-open: let this one call through. If it fails, failed() puts the
	// breaker straight back to the threshold rather than starting the run over.
	b.failures = cacheLeaseBreakerThreshold - 1

	return false
}

func (b *leaseBreaker) failed() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.failures++
	if b.failures >= cacheLeaseBreakerThreshold {
		b.openedAt = b.clock()
	}
}

func (b *leaseBreaker) succeeded() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.failures = 0
}
