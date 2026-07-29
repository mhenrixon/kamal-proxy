package server

import (
	"context"
	"sort"
)

// The in-process store knows exactly what it holds, so none of this is
// estimated and none of it costs a round trip. Stats is one mutex acquisition.

func (s *memoryCacheStore) Stats(ctx context.Context, options CacheStatsOptions) (CacheStats, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	stats := CacheStats{
		Store: CacheStoreMemory,
		// Nobody else can see an in-process cache, so every number below is
		// first-hand and there is no server to describe.
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

// serviceBreakdown must be called with the lock held. It is sorted by size so
// the service filling the cache reads first.
func (s *memoryCacheStore) serviceBreakdown() []CacheServiceStats {
	if len(s.services) == 0 {
		return nil
	}

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
