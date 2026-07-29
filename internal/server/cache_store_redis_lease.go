package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// releaseCacheLease drops a lease only if this caller still holds it. Compare
// and delete has to be one atomic step: between a read and a delete the lease
// could expire and be claimed by another proxy, and deleting it then would hand
// a third proxy the fetch the lease exists to prevent.
var releaseCacheLease = redis.NewScript(`
	if redis.call("GET", KEYS[1]) == ARGV[1] then
		return redis.call("DEL", KEYS[1])
	end
	return 0
`)

// AcquireLease claims the right to fetch a key for the whole fleet.
//
// One command, one round trip, and Redis owns the expiry -- no clock is ever
// compared between proxies, which is what keeps this correct when their clocks
// disagree.
func (s *redisCacheStore) AcquireLease(ctx context.Context, key string, ttl time.Duration) CacheLease {
	if ttl <= 0 {
		return CacheLease{Outcome: CacheLeaseUnavailable}
	}

	// A store that has been failing is not worth a timeout on every miss.
	if s.leaseBreaker.open() {
		return CacheLease{Outcome: CacheLeaseDeferred}
	}

	token, ok := newLeaseToken()
	if !ok {
		// Without a token we could never safely release, so do not claim.
		return CacheLease{Outcome: CacheLeaseUnavailable}
	}

	leaseKey := cacheLeaseKey(key)

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	acquired, err := s.client.SetNX(ctx, leaseKey, token, ttl).Result()
	if err != nil {
		s.leaseBreaker.failed()
		slog.Debug("Cache lease unavailable", "key", leaseKey, "error", err)
		return CacheLease{Outcome: CacheLeaseUnavailable}
	}

	s.leaseBreaker.succeeded()

	if !acquired {
		return CacheLease{Outcome: CacheLeaseTaken, Key: leaseKey}
	}

	return CacheLease{Outcome: CacheLeaseAcquired, Key: leaseKey, Token: token}
}

// ProbeLease reads the entry and its lease together, so a waiter cannot see the
// lease released between two calls and give up on an entry already sitting
// there.
func (s *redisCacheStore) ProbeLease(ctx context.Context, key string) (*CacheEntry, bool) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	values, err := s.client.MGet(ctx, key, cacheLeaseKey(key)).Result()
	if err != nil || len(values) != 2 {
		// The store stopped answering. Report the holder as gone rather than
		// leaving a caller waiting on a question nobody will answer.
		if err != nil {
			s.leaseBreaker.failed()
			slog.Debug("Cache lease probe failed", "key", key, "error", err)
		}
		return nil, false
	}

	s.leaseBreaker.succeeded()

	held := values[1] != nil

	data, ok := values[0].(string)
	if !ok {
		return nil, held
	}

	entry, err := decodeCacheEntry([]byte(data))
	if err != nil {
		slog.Debug("Discarding undecodable cache entry", "key", key, "error", err)
		return nil, held
	}

	return entry, held
}

// ReleaseLease hands the key back as soon as the outcome is known, rather than
// holding the fleet off for the rest of the TTL.
func (s *redisCacheStore) ReleaseLease(ctx context.Context, lease CacheLease) {
	if !lease.mine() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if err := releaseCacheLease.Run(ctx, s.client, []string{lease.Key}, lease.Token).Err(); err != nil && err != redis.Nil {
		// Nothing to do about it: the lease expires on its own, and the cost is
		// that the fleet waits out the remainder of the TTL once.
		slog.Debug("Failed to release cache lease", "key", lease.Key, "error", err)
	}
}
