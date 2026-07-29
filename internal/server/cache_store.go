package server

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	// CacheStoreMemory keeps entries in this process. Each proxy in a fleet then
	// has its own cache, which still collapses repeat requests per node but does
	// not share a fetch between nodes.
	CacheStoreMemory = "memory"

	// DefaultCacheMemorySize caps the in-process store. Entries past it are
	// evicted least-recently-used first.
	DefaultCacheMemorySize = 256 * MB

	// DefaultCacheStoreTimeout bounds a shared store's read or write. It is
	// short on purpose: a cache that takes longer than this to answer has
	// already cost more than the miss it was meant to save.
	DefaultCacheStoreTimeout = 100 * time.Millisecond

	// CacheStoreRedis names the shared store.
	CacheStoreRedis = "redis"

	// DefaultCacheLeaseTTL bounds how long one proxy's claim on a key outlives
	// the proxy itself. A holder releases the moment it knows the outcome, so
	// this only matters when a node is killed mid-fetch or its fetch outran the
	// lease -- and then the cost is a duplicated fetch, never a wrong answer. It
	// is long enough to cover a slow origin, because a lease that lapses
	// mid-fetch reintroduces exactly the duplicate this removes.
	DefaultCacheLeaseTTL = 10 * time.Second

	// DefaultCacheLeaseWait is how long a proxy on a cold miss waits for another
	// proxy's fetch to land before going to the target itself.
	DefaultCacheLeaseWait = 500 * time.Millisecond
)

// CacheStore holds stored responses. Implementations must fail open -- a store
// that is unreachable turns every lookup into a miss and every write into a
// logged error, and never into a failed request.
type CacheStore interface {
	// Get returns the entry stored under key, if there is one.
	Get(ctx context.Context, key string) (*CacheEntry, bool)
	// Set stores an entry for as long as it can still be of use. An entry with
	// nothing left to live is dropped rather than stored.
	Set(ctx context.Context, key string, entry *CacheEntry) error
	// Purge removes a service's entries, optionally only those below a path
	// prefix, and reports how many it removed.
	Purge(ctx context.Context, service, pathPrefix string) (int, error)
	Close() error
}

// CacheLeaser is the optional half of a CacheStore: a store several proxies
// share can also arbitrate which of them fetches a key, so a lifetime rolling
// over costs the application one request for the whole fleet rather than one per
// node.
//
// A store nobody else can see does not implement it. On a single proxy the
// in-process single flight already is the lease, and arbitrating with nobody
// would cost a round trip to learn what is already known -- so the memory store
// deliberately has none of these methods, and the middleware's nil check is the
// whole of what a single-node deployment pays.
//
// Every method fails open. Nothing that is served may depend on holding a lease,
// and nothing is withheld for want of one.
type CacheLeaser interface {
	// AcquireLease claims the right to fetch key on the fleet's behalf for at
	// most ttl. Only CacheLeaseTaken means another proxy is already fetching;
	// every other outcome means "you fetch".
	AcquireLease(ctx context.Context, key string, ttl time.Duration) CacheLease

	// ProbeLease reads the entry stored under key and whether anyone still holds
	// its lease, in one round trip. Both answers together on purpose: a probe
	// that took two could see the lease released between them and give up on an
	// entry that was already there.
	//
	// A false second return is what turns "the holder died" from a timeout into
	// a signal -- and so is an unreachable store, which stops a caller waiting
	// on a question nobody is answering.
	ProbeLease(ctx context.Context, key string) (*CacheEntry, bool)

	// ReleaseLease drops a lease this caller holds, so a fetch that ended early
	// does not hold the rest of the fleet off for the remainder of the ttl. It
	// is a no-op for a lease this caller does not hold: releasing one that
	// expired and was claimed by another proxy would hand a third the fetch the
	// lease exists to prevent.
	ReleaseLease(ctx context.Context, lease CacheLease)
}

type CacheStoreConfig struct {
	// URL is "memory" (or empty) for the in-process store, or a redis:// or
	// rediss:// URL for a store shared by every proxy pointed at it.
	URL string
	// MemorySize caps the in-process store. Zero means DefaultCacheMemorySize.
	MemorySize int64
	// Timeout bounds each shared-store operation. Zero means
	// DefaultCacheStoreTimeout.
	Timeout time.Duration
}

func (c CacheStoreConfig) memorySize() int64 {
	if c.MemorySize <= 0 {
		return DefaultCacheMemorySize
	}
	return c.MemorySize
}

func (c CacheStoreConfig) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultCacheStoreTimeout
	}
	return c.Timeout
}

func NewCacheStore(config CacheStoreConfig) (CacheStore, error) {
	if isMemoryCacheStoreURL(config.URL) {
		return newMemoryCacheStore(config.memorySize()), nil
	}

	if isRedisCacheStoreURL(config.URL) {
		return newRedisCacheStore(config)
	}

	return nil, unsupportedCacheStoreError(config.URL)
}

// ParseCacheStoreURL reports whether a store URL is one this proxy can open,
// without opening it. The run command uses it to reject a typo at startup
// rather than at the first cached request.
func ParseCacheStoreURL(url string) error {
	if isMemoryCacheStoreURL(url) {
		return nil
	}

	if isRedisCacheStoreURL(url) {
		_, err := parseRedisCacheStoreURL(url)
		return err
	}

	return unsupportedCacheStoreError(url)
}

// Private

func isMemoryCacheStoreURL(url string) bool {
	return url == "" || url == CacheStoreMemory
}

func isRedisCacheStoreURL(url string) bool {
	return strings.HasPrefix(url, "redis://") || strings.HasPrefix(url, "rediss://")
}

func unsupportedCacheStoreError(url string) error {
	return fmt.Errorf("cache-store must be %q or a redis:// or rediss:// URL, got %q", CacheStoreMemory, url)
}
