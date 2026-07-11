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
