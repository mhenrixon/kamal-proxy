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
