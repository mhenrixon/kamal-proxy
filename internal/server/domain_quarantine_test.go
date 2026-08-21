package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testQuarantineAt(now time.Time) (*domainQuarantine, *time.Time) {
	current := now
	q := newDomainQuarantine()
	q.now = func() time.Time { return current }
	return q, &current
}

func TestDomainQuarantine_ACMEBackoffProgression(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())

	tests := []struct {
		failure  int
		expected time.Duration
	}{
		{1, 15 * time.Minute},
		{2, time.Hour},
		{3, 4 * time.Hour},
		{4, 24 * time.Hour},
		{5, 24 * time.Hour}, // capped
	}

	for _, tt := range tests {
		backoff := q.RecordFailure("bad.example.com", quarantineACME)
		assert.Equal(t, tt.expected, backoff, "failure %d", tt.failure)
	}
}

func TestDomainQuarantine_PreflightBackoffStartsGentler(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())

	assert.Equal(t, 5*time.Minute, q.RecordFailure("new.example.com", quarantinePreflight))
	assert.Equal(t, 15*time.Minute, q.RecordFailure("new.example.com", quarantinePreflight))
}

func TestDomainQuarantine_ExpiresAndClears(t *testing.T) {
	start := time.Now()
	q, current := testQuarantineAt(start)

	q.RecordFailure("bad.example.com", quarantineACME)
	assert.True(t, q.IsQuarantined("bad.example.com"))
	assert.False(t, q.IsQuarantined("good.example.com"))

	// Past the backoff window the domain is eligible again, but the failure
	// count is retained for the next backoff step.
	*current = start.Add(16 * time.Minute)
	assert.False(t, q.IsQuarantined("bad.example.com"))
	assert.Equal(t, time.Hour, q.RecordFailure("bad.example.com", quarantineACME))

	q.Clear("bad.example.com")
	assert.False(t, q.IsQuarantined("bad.example.com"))
	assert.Equal(t, 15*time.Minute, q.RecordFailure("bad.example.com", quarantineACME))
}

func TestDomainQuarantine_RecordRateLimitedHoldsUntilAdvertisedTime(t *testing.T) {
	start := time.Now()
	q, current := testQuarantineAt(start)

	retryAfter := start.Add(2 * time.Hour)
	backoff := q.RecordRateLimited("limited.example.com", retryAfter)
	assert.Equal(t, 2*time.Hour+time.Minute, backoff, "hold must include the safety margin")
	assert.True(t, q.IsQuarantined("limited.example.com"))

	// Held right up to the advertised time plus margin, then released.
	*current = retryAfter.Add(30 * time.Second)
	assert.True(t, q.IsQuarantined("limited.example.com"))
	*current = retryAfter.Add(2 * time.Minute)
	assert.False(t, q.IsQuarantined("limited.example.com"))

	// The failure still counts toward the ladder history.
	snapshot := q.Snapshot()
	require.Contains(t, snapshot, "limited.example.com")
	assert.Equal(t, 1, snapshot["limited.example.com"].Failures)
	assert.Equal(t, time.Hour, q.RecordFailure("limited.example.com", quarantineACME))
}

func TestDomainQuarantine_RecordRateLimitedFallsBackToLadder(t *testing.T) {
	start := time.Now()
	q, _ := testQuarantineAt(start)

	// No advertised time: first ACME ladder step.
	assert.Equal(t, 15*time.Minute, q.RecordRateLimited("limited.example.com", time.Time{}))

	// An advertised time already in the past is no better than none.
	assert.Equal(t, time.Hour, q.RecordRateLimited("limited.example.com", start.Add(-time.Hour)))
}

func TestDomainQuarantine_Filter(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())

	q.RecordFailure("bad.example.com", quarantineACME)

	allowed, quarantined := q.Filter([]string{"a.example.com", "bad.example.com", "b.example.com"})
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, allowed)
	assert.Equal(t, []string{"bad.example.com"}, quarantined)
}

func TestDomainQuarantine_SnapshotRestore(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())

	q.RecordFailure("bad.example.com", quarantineACME)
	q.RecordFailure("bad.example.com", quarantineACME)

	snapshot := q.Snapshot()
	require.Contains(t, snapshot, "bad.example.com")
	assert.Equal(t, 2, snapshot["bad.example.com"].Failures)

	restored, _ := testQuarantineAt(time.Now())
	restored.Restore(snapshot)
	assert.True(t, restored.IsQuarantined("bad.example.com"))
	assert.Equal(t, 4*time.Hour, restored.RecordFailure("bad.example.com", quarantineACME))
}
