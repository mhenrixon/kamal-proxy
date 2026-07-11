package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTokenBucketAt(capacity int, refill time.Duration, start time.Time) (*tokenBucket, *time.Time) {
	current := start
	b := newTokenBucket(capacity, refill)
	b.now = func() time.Time { return current }
	return b, &current
}

func TestTokenBucket_BurstThenDeny(t *testing.T) {
	b, _ := testTokenBucketAt(3, time.Minute, time.Now())

	assert.True(t, b.TryTake())
	assert.True(t, b.TryTake())
	assert.True(t, b.TryTake())
	assert.False(t, b.TryTake())
}

func TestTokenBucket_Refills(t *testing.T) {
	start := time.Now()
	b, current := testTokenBucketAt(2, time.Minute, start)

	require.True(t, b.TryTake())
	require.True(t, b.TryTake())
	require.False(t, b.TryTake())

	*current = start.Add(30 * time.Second)
	assert.False(t, b.TryTake(), "no token before a full refill interval")

	*current = start.Add(time.Minute)
	assert.True(t, b.TryTake())
	assert.False(t, b.TryTake())

	// Refill accumulates but never exceeds capacity
	*current = start.Add(time.Hour)
	assert.True(t, b.TryTake())
	assert.True(t, b.TryTake())
	assert.False(t, b.TryTake())
}

func TestTokenBucket_TakeHonorsContext(t *testing.T) {
	b, _ := testTokenBucketAt(1, time.Hour, time.Now())
	require.True(t, b.TryTake())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := b.Take(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
