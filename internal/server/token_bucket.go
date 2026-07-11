package server

import (
	"context"
	"sync"
	"time"
)

// tokenBucket is a simple token bucket: `capacity` tokens available at once,
// one token restored every `refillInterval`. It rate-limits ACME order
// creation well below Let's Encrypt's account limits.
type tokenBucket struct {
	mu             sync.Mutex
	tokens         int
	capacity       int
	refillInterval time.Duration
	lastRefill     time.Time
	now            func() time.Time
}

func newTokenBucket(capacity int, refillInterval time.Duration) *tokenBucket {
	b := &tokenBucket{
		tokens:         capacity,
		capacity:       capacity,
		refillInterval: refillInterval,
		now:            time.Now,
	}
	b.lastRefill = b.now()
	return b
}

// TryTake takes a token if one is available.
func (b *tokenBucket) TryTake() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill()
	if b.tokens == 0 {
		return false
	}
	b.tokens--
	return true
}

// Take blocks until a token is available or the context is done.
func (b *tokenBucket) Take(ctx context.Context) error {
	for {
		if b.TryTake() {
			return nil
		}

		timer := time.NewTimer(b.nextTokenIn())
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Private

func (b *tokenBucket) refill() {
	if b.tokens >= b.capacity {
		b.lastRefill = b.now()
		return
	}

	elapsed := b.now().Sub(b.lastRefill)
	replenished := int(elapsed / b.refillInterval)
	if replenished == 0 {
		return
	}

	b.tokens = min(b.tokens+replenished, b.capacity)
	b.lastRefill = b.lastRefill.Add(time.Duration(replenished) * b.refillInterval)
}

func (b *tokenBucket) nextTokenIn() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	wait := b.refillInterval - b.now().Sub(b.lastRefill)
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return wait
}
