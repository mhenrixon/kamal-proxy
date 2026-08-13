package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTracker captures cache events; everything else is a no-op.
type recordingTracker struct {
	nullTracker
	mu     sync.Mutex
	events map[string]int
}

func (r *recordingTracker) TrackCacheEvent(service, result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.events == nil {
		r.events = map[string]int{}
	}
	r.events[service+":"+result]++
}

func (r *recordingTracker) eventCount(service, result string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.events[service+":"+result]
}

func TestSetTracker_DelegatesEventsAndRestores(t *testing.T) {
	recording := &recordingTracker{}
	previous := SetTracker(recording)
	t.Cleanup(func() { SetTracker(previous) })

	Tracker.TrackCacheEvent("service1", "hit")
	assert.Equal(t, 1, recording.eventCount("service1", "hit"))

	restored := SetTracker(previous)
	assert.Same(t, recording, restored, "SetTracker returns the tracker it replaced")

	Tracker.TrackCacheEvent("service1", "hit")
	assert.Equal(t, 1, recording.eventCount("service1", "hit"), "events after restore must not reach the removed tracker")
}

// Two Enable calls happen whenever a second metrics-enabled Server starts in
// the same process -- most importantly `go test -count=2`. The second call must
// reuse the registered collectors instead of panicking on re-registration.
func TestEnable_IsIdempotent(t *testing.T) {
	require.NotPanics(t, func() {
		require.NotNil(t, Enable())
		require.NotNil(t, Enable())
	})
}

// A tracker installed after Enable (a test fake) must survive further Enable
// calls -- Enable clobbering it is what made cache-metric assertions depend on
// which tests ran before them.
func TestEnable_DoesNotReplaceATrackerInstalledAfterIt(t *testing.T) {
	Enable()

	recording := &recordingTracker{}
	previous := SetTracker(recording)
	t.Cleanup(func() { SetTracker(previous) })

	Enable()

	Tracker.TrackCacheEvent("service1", "miss")
	assert.Equal(t, 1, recording.eventCount("service1", "miss"))
}

// Swapping the tracker while request goroutines emit through it must be free
// of data races (run with -race).
func TestSetTracker_IsSafeUnderConcurrentEmission(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			Tracker.TrackRequest("service1", "GET", 200, time.Millisecond)
		}
	}()

	original := SetTracker(&recordingTracker{})
	for range 100 {
		SetTracker(&recordingTracker{})
	}
	SetTracker(original)
	<-done
}

func TestNormalizeMethod(t *testing.T) {
	assert.Equal(t, "GET", normalizeMethod("GET"))
	assert.Equal(t, "POST", normalizeMethod("POST"))
	assert.Equal(t, "PATCH", normalizeMethod("PATCH"))

	assert.Equal(t, "OTHER", normalizeMethod("CUSTOM"))
	assert.Equal(t, "OTHER", normalizeMethod("OTHER"))
	assert.Equal(t, "OTHER", normalizeMethod(""))
}
