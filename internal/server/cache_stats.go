package server

import (
	"context"
	"slices"
	"time"
)

// --cache-memory-size defaults to 256MB and could only ever be tuned by
// guesswork: the store knew what it held and what it had dropped, and told
// nobody. These types are that answer.
//
// The shape is driven by one distinction: what this proxy can vouch for, kept
// apart from what a shared server merely says about itself. The second is not
// about this cache at all -- a Redis reports on its whole keyspace, including
// keys this proxy never wrote -- and putting that in the type name is the only
// mitigation a dashboard cannot lose.

// cacheStatsTimeout bounds a stats read. It answers an operator rather than a
// request, so it can afford more than the per-request budget.
const cacheStatsTimeout = 5 * time.Second

// CacheReporter is the optional half of a CacheStore that can describe itself.
//
// Unlike the request path, a stats read reports its errors rather than failing
// open: an operator asking how full the cache is deserves the failure, not a
// convincing zero.
type CacheReporter interface {
	Stats(ctx context.Context, options CacheStatsOptions) (CacheStats, error)
}

// CacheStatsOptions asks for numbers a store has to work for.
type CacheStatsOptions struct {
	// Count breaks the numbers down by service, and on a shared store attributes
	// entries and bytes to this cache at all. Off by default: on Redis it means
	// walking the keyspace, and it is the only truthful answer a shared store
	// has to "how big is *my* cache".
	Count bool `json:"count"`
}

// CacheStats answers the two questions --cache-memory-size poses: is the budget
// big enough, and what is filling it.
type CacheStats struct {
	// Store is CacheStoreMemory or CacheStoreRedis.
	Store string `json:"store"`
	// Shared reports whether other proxies write to the same store.
	Shared bool `json:"shared"`

	// Local is first-hand: what this proxy's cache is holding and what it has
	// dropped.
	Local CacheLocalStats `json:"local"`

	// Server is what a shared store says about itself, and is nil for the
	// in-process store. EVERY number in it describes the whole instance,
	// including keys this proxy never wrote.
	Server *CacheServerStats `json:"server,omitempty"`
}

// CacheLocalStats is exact. Entries and Bytes are what this proxy holds; a
// shared store holds nothing here and fills them only when asked to count.
type CacheLocalStats struct {
	// Counted says whether Entries and Bytes were measured at all, so a zero
	// that means "not asked" cannot be read as "empty".
	Counted bool  `json:"counted"`
	Entries int64 `json:"entries"`
	// Bytes is the in-process footprint for the memory store, including the flat
	// per-entry overhead allowance; for a counted Redis store it is the size of
	// the encoded values, which is a smaller and different thing.
	Bytes int64 `json:"bytes"`
	// MaxBytes is the budget this proxy enforces, and is zero for a shared
	// store, which is bounded by its own maxmemory rather than by anything set
	// here.
	MaxBytes int64 `json:"max_bytes"`

	// EvictedFresh is THE number that says the budget is too small: an entry
	// pushed out with lifetime still on it was fetched and never fully used. A
	// full cache evicting only stale entries is a cache doing its job, which is
	// why a single eviction count answers nothing. Entries that merely expired
	// on lookup are in neither: expiry says nothing about the budget.
	EvictedFresh int64 `json:"evicted_fresh"`
	EvictedStale int64 `json:"evicted_stale"`
	// Oversized counts responses refused because one alone exceeded the whole
	// budget -- a misconfiguration rather than pressure.
	Oversized int64 `json:"oversized"`

	// Services breaks Entries and Bytes down by the service that stored them,
	// which is what names the service filling the cache. Present only with
	// CacheStatsOptions.Count.
	Services []CacheServiceStats `json:"services,omitempty"`
}

type CacheServiceStats struct {
	Service string `json:"service"`
	Entries int64  `json:"entries"`
	Bytes   int64  `json:"bytes"`
}

// CacheServerStats is instance-wide and shared with anything else using the same
// server.
type CacheServerStats struct {
	// Keys is every key in the selected database: this proxy's entries plus
	// every other proxy's, plus live leases, plus anything else sharing the db.
	// It is this cache's entry count only when the cache has a database to
	// itself.
	Keys      int64 `json:"keys"`
	UsedBytes int64 `json:"used_bytes"`
	MaxBytes  int64 `json:"max_bytes"`
	// Policy is the server's eviction policy. "noeviction" on a full instance
	// means writes are refused and the cache silently stops filling, which is
	// the one value here worth alerting on.
	Policy string `json:"eviction_policy"`

	// Unavailable names the fields the server declined to answer, so a managed
	// Redis that restricts INFO reads as unknown rather than as zero.
	Unavailable []string `json:"unavailable,omitempty"`
}

// Unknown reports whether a field was withheld by the server rather than
// measured as zero.
func (s *CacheServerStats) Unknown(field string) bool {
	return slices.Contains(s.Unavailable, field)
}

// Eviction states, as a metric label.
const (
	// cacheEvictionFresh is an entry dropped with lifetime still on it: fetched
	// and never fully used, which is what says the budget is too small.
	cacheEvictionFresh = "fresh"
	// cacheEvictionStale is an entry dropped past its usefulness, which is a
	// cache doing its job.
	cacheEvictionStale = "stale"
)
