package server

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

// What a shared store can honestly say about itself is narrower than it looks,
// and the gap matters when someone is sizing a cache:
//
//   - This proxy's byte footprint, for free: NO. There is no way to ask Redis
//     how much memory kp:c:* occupies. --count walks the keyspace for it.
//   - This proxy's entry count, for free: NO. DBSIZE is O(1) and reported, but
//     it counts every key in the database -- other proxies' entries, live
//     leases, and anything else sharing it.
//   - Memory and eviction policy: instance-wide only, and often withheld
//     entirely by a managed Redis that restricts INFO.
//
// Anything the server declines to answer is named in Unavailable rather than
// reported as zero. A zero an operator believes is worse than an absence they
// can see.

// redisStatsScanBatch is the COUNT hint for the --count walk. Same trade as
// Purge's: an operator action, so a larger batch buys fewer round trips.
const redisStatsScanBatch = 256

func (s *redisCacheStore) Stats(ctx context.Context, options CacheStatsOptions) (CacheStats, error) {
	ctx, cancel := context.WithTimeout(ctx, cacheStatsTimeout)
	defer cancel()

	stats := CacheStats{
		Store: CacheStoreRedis,
		// The whole point of a shared store: somebody else is writing here too.
		Shared: true,
		Local:  CacheLocalStats{},
	}

	server, err := s.serverStats(ctx)
	if err != nil {
		return CacheStats{}, err
	}
	stats.Server = server

	if options.Count {
		local, err := s.countEntries(ctx)
		if err != nil {
			return CacheStats{}, err
		}
		stats.Local = local
	}

	return stats, nil
}

// Private

// serverStats reads what the instance says about itself.
//
// The two commands are issued separately rather than pipelined, because their
// failures mean different things and a pipeline cannot keep them apart: DBSIZE
// failing means the connection is unusable, while INFO failing is the ordinary
// case of a managed Redis restricting it. Pipelining also proved to swallow both
// errors outright -- on a closed server Exec reports the failure but each
// command still returns a zero value with a nil error, which would have made a
// dead store read as an empty one.
func (s *redisCacheStore) serverStats(ctx context.Context) (*CacheServerStats, error) {
	keys, err := s.client.DBSize(ctx).Result()
	if err != nil {
		// Nothing to report: the connection itself is gone.
		return nil, fmt.Errorf("failed to read cache store size: %w", err)
	}

	stats := &CacheServerStats{Keys: keys}

	payload, err := s.client.Info(ctx, "memory").Result()
	if err != nil {
		// A managed Redis restricting INFO is expected, not an error. Name what
		// is missing rather than reporting zeros.
		stats.Unavailable = []string{"used_bytes", "max_bytes", "eviction_policy"}
		return stats, nil
	}

	fields := parseRedisInfo(payload)

	if used, ok := parseRedisInt(fields, "used_memory"); ok {
		stats.UsedBytes = used
	} else {
		stats.Unavailable = append(stats.Unavailable, "used_bytes")
	}

	if max, ok := parseRedisInt(fields, "maxmemory"); ok {
		stats.MaxBytes = max
	} else {
		stats.Unavailable = append(stats.Unavailable, "max_bytes")
	}

	if policy, ok := fields["maxmemory_policy"]; ok {
		stats.Policy = policy
	} else {
		stats.Unavailable = append(stats.Unavailable, "eviction_policy")
	}

	return stats, nil
}

// countEntries walks this cache's keys and measures them. It is opt-in because
// it is O(keyspace) -- the same scan Purge pays for, plus a STRLEN per key.
//
// The bytes it reports are the size of the encoded values, which is smaller than
// and not comparable to the memory store's in-process figure.
func (s *redisCacheStore) countEntries(ctx context.Context) (CacheLocalStats, error) {
	local := CacheLocalStats{Counted: true}
	usage := map[string]*cacheServiceUsage{}

	cursor := uint64(0)
	for {
		keys, next, err := s.client.Scan(ctx, cursor, cacheKeyPrefix+"*", redisStatsScanBatch).Result()
		if err != nil {
			return CacheLocalStats{}, fmt.Errorf("failed to scan cache entries: %w", err)
		}

		if len(keys) > 0 {
			sizes, err := s.entrySizes(ctx, keys)
			if err != nil {
				return CacheLocalStats{}, err
			}

			for i, size := range sizes {
				if size <= 0 {
					// Expired between the scan and the measurement.
					continue
				}

				local.Entries++
				local.Bytes += size

				service := serviceFromCacheKey(keys[i])
				if usage[service] == nil {
					usage[service] = &cacheServiceUsage{}
				}
				usage[service].entries++
				usage[service].bytes += size
			}
		}

		cursor = next
		if cursor == 0 {
			break
		}
	}

	local.Services = serviceStatsFrom(usage)

	return local, nil
}

func (s *redisCacheStore) entrySizes(ctx context.Context, keys []string) ([]int64, error) {
	pipeline := s.client.Pipeline()

	lengths := make([]*redis.IntCmd, len(keys))
	for i, key := range keys {
		lengths[i] = pipeline.StrLen(ctx, key)
	}

	if _, err := pipeline.Exec(ctx); err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to measure cache entries: %w", err)
	}

	sizes := make([]int64, len(keys))
	for i, length := range lengths {
		size, err := length.Result()
		if err != nil {
			// Gone between the scan and here; not an error worth failing over.
			continue
		}
		sizes[i] = size
	}

	return sizes, nil
}

// serviceFromCacheKey reads the service back out of "kp:c:<service>:<hash>". The
// hash never contains a colon, so the service is everything between the prefix
// and the last one -- which is what keeps a service name containing a colon
// readable.
func serviceFromCacheKey(key string) string {
	trimmed := strings.TrimPrefix(key, cacheKeyPrefix)

	if index := strings.LastIndex(trimmed, ":"); index >= 0 {
		return trimmed[:index]
	}

	return trimmed
}

func serviceStatsFrom(usage map[string]*cacheServiceUsage) []CacheServiceStats {
	if len(usage) == 0 {
		return nil
	}

	breakdown := make([]CacheServiceStats, 0, len(usage))
	for service, counts := range usage {
		breakdown = append(breakdown, CacheServiceStats{
			Service: service,
			Entries: counts.entries,
			Bytes:   counts.bytes,
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

// parseRedisInfo turns an INFO payload into its fields. Section headings ("#
// Memory") and blank lines are not fields, and a field the server did not send
// is absent rather than empty -- the caller distinguishes "withheld" from "zero"
// on exactly that.
func parseRedisInfo(payload string) map[string]string {
	fields := map[string]string{}

	for line := range strings.SplitSeq(payload, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}

		fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}

	return fields
}

func parseRedisInt(fields map[string]string, name string) (int64, bool) {
	value, found := fields[name]
	if !found {
		return 0, false
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}

	return parsed, true
}
