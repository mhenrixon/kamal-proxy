package server

import (
	"context"
	"sort"
)

// The file store keeps an index of everything it wrote, so these numbers are
// first-hand and cost one mutex acquisition -- no directory walk, and no round
// trip. `kamal-proxy cache stats` reporting nothing for a file store would be a
// worse experience than for the two stores that do report.

func (s *fileCacheStore) Stats(ctx context.Context, options CacheStatsOptions) (CacheStats, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	stats := CacheStats{
		Store: CacheStoreFile,
		// A directory on one host is not a fleet-shared store. Two proxies
		// pointed at the same path would each keep their own index, which is why
		// this reports false and why the store implements no CacheLeaser.
		Shared: false,
		Local: CacheLocalStats{
			Counted:      true,
			Entries:      int64(len(s.records)),
			Bytes:        s.bytes,
			MaxBytes:     s.maxBytes,
			EvictedFresh: s.evictedFresh,
			EvictedStale: s.evictedStale,
			Oversized:    s.oversized,
		},
	}

	if options.Count {
		stats.Local.Services = s.serviceBreakdown()
	}

	return stats, nil
}

// serviceBreakdown must be called with the lock held. Sorted by size so the
// service filling the cache reads first.
func (s *fileCacheStore) serviceBreakdown() []CacheServiceStats {
	breakdown := make([]CacheServiceStats, 0, len(s.services))
	for service, usage := range s.services {
		breakdown = append(breakdown, CacheServiceStats{
			Service: service,
			Entries: usage.entries,
			Bytes:   usage.bytes,
		})
	}

	sort.Slice(breakdown, func(i, j int) bool {
		if breakdown[i].Bytes != breakdown[j].Bytes {
			return breakdown[i].Bytes > breakdown[j].Bytes
		}
		return breakdown[i].Service < breakdown[j].Service
	})

	return breakdown
}
