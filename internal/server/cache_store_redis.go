package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// redisScanBatch is the COUNT hint for the purge scan. Purging is an
	// operator action, not a request path, so a larger batch trades a longer
	// single call for fewer round trips.
	redisScanBatch = 256

	// cachePurgeTimeout bounds a whole purge, which walks the keyspace and so
	// cannot live inside the per-operation budget a lookup uses.
	cachePurgeTimeout = 30 * time.Second
)

// redisCacheStore is the shared store: every proxy pointed at one Redis answers
// from the same entries, so a hot URL costs the application one fetch for the
// whole fleet rather than one per node.
//
// Redis owns expiry -- each entry is written with the TTL it has left -- so
// nothing here has to sweep, and a proxy that restarts finds the cache warm.
type redisCacheStore struct {
	client  redis.UniversalClient
	timeout time.Duration
}

func newRedisCacheStore(config CacheStoreConfig) (*redisCacheStore, error) {
	options, err := parseRedisCacheStoreURL(config.URL)
	if err != nil {
		return nil, err
	}

	timeout := config.timeout()

	// Fail fast rather than retry: a cache lookup that is still going after the
	// budget has cost the request more than the miss it was avoiding, and the
	// caller treats an error as a miss anyway.
	options.MaxRetries = -1
	options.DialTimeout = timeout
	options.ReadTimeout = timeout
	options.WriteTimeout = timeout

	return &redisCacheStore{
		client:  redis.NewClient(options),
		timeout: timeout,
	}, nil
}

func (s *redisCacheStore) Get(ctx context.Context, key string) (*CacheEntry, bool) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		// A miss is the common case and not worth a log line; anything else is
		// the store being unwell, which is worth knowing about but never worth
		// failing the request over.
		if !errors.Is(err, redis.Nil) {
			slog.Debug("Cache store lookup failed", "key", key, "error", err)
		}
		return nil, false
	}

	entry, err := decodeCacheEntry(data)
	if err != nil {
		// Written by a version that framed entries differently, or corrupted.
		// Either way it is not usable, and the miss will overwrite it.
		slog.Debug("Discarding undecodable cache entry", "key", key, "error", err)
		return nil, false
	}

	return entry, true
}

func (s *redisCacheStore) Set(ctx context.Context, key string, entry *CacheEntry) error {
	ttl := entry.ttl()
	if ttl <= 0 {
		return nil
	}

	data, err := encodeCacheEntry(entry)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store cache entry: %w", err)
	}

	return nil
}

func (s *redisCacheStore) Purge(ctx context.Context, service, pathPrefix string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, cachePurgeTimeout)
	defer cancel()

	pattern := cacheKeyPrefix + escapeRedisGlob(service) + ":*"
	purged := 0
	cursor := uint64(0)

	for {
		keys, next, err := s.client.Scan(ctx, cursor, pattern, redisScanBatch).Result()
		if err != nil {
			return purged, fmt.Errorf("failed to scan cache entries: %w", err)
		}

		matched, err := s.keysBelowPath(ctx, keys, pathPrefix)
		if err != nil {
			return purged, err
		}

		if len(matched) > 0 {
			deleted, err := s.client.Del(ctx, matched...).Result()
			if err != nil {
				return purged, fmt.Errorf("failed to remove cache entries: %w", err)
			}
			purged += int(deleted)
		}

		cursor = next
		if cursor == 0 {
			return purged, nil
		}
	}
}

func (s *redisCacheStore) Close() error {
	return s.client.Close()
}

// Private

// keysBelowPath narrows a batch of scanned keys to those whose entry sits below
// pathPrefix. It has to read the entries to find out, because the path is inside
// them rather than in the key -- a key carrying a raw path would need escaping
// the scan pattern cannot express. Purging is rare enough to pay for that.
func (s *redisCacheStore) keysBelowPath(ctx context.Context, keys []string, pathPrefix string) ([]string, error) {
	if pathPrefix == "" || len(keys) == 0 {
		return keys, nil
	}

	values, err := s.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to read cache entries: %w", err)
	}

	matched := make([]string, 0, len(keys))
	for i, value := range values {
		data, ok := value.(string)
		if !ok {
			// Expired between the scan and this read; nothing left to remove.
			continue
		}

		entry, err := decodeCacheEntry([]byte(data))
		if err != nil {
			// Unreadable entries are removed rather than left behind forever.
			matched = append(matched, keys[i])
			continue
		}

		if strings.HasPrefix(entry.Path, pathPrefix) {
			matched = append(matched, keys[i])
		}
	}

	return matched, nil
}

func parseRedisCacheStoreURL(url string) (*redis.Options, error) {
	options, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("invalid cache-store URL: %w", err)
	}

	return options, nil
}

// escapeRedisGlob neutralizes the pattern metacharacters in a service name, so
// a service called "a*" purges its own entries rather than every service's.
func escapeRedisGlob(value string) string {
	var escaped strings.Builder
	escaped.Grow(len(value))

	for _, char := range value {
		switch char {
		case '\\', '*', '?', '[', ']':
			escaped.WriteRune('\\')
		}
		escaped.WriteRune(char)
	}

	return escaped.String()
}
