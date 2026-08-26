package server

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type probeRecorder struct {
	mu      sync.Mutex
	probed  []string
	failing map[string]bool
}

func newProbeRecorder(failing ...string) *probeRecorder {
	r := &probeRecorder{failing: map[string]bool{}}
	for _, domain := range failing {
		r.failing[domain] = true
	}
	return r
}

func (r *probeRecorder) probe(domain string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.probed = append(r.probed, domain)
	if r.failing[domain] {
		return errors.New("does not route here")
	}
	return nil
}

func (r *probeRecorder) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string{}, r.probed...)
}

func testReleaseProber(q *domainQuarantine, config releaseProberConfig) *releaseProber {
	if config.Preflight == nil {
		config.Preflight = func(string) error { return nil }
	}
	return newReleaseProber(q, config)
}

// The point of the whole feature: a domain held because it did not route here
// is eligible again as soon as it does, without waiting out its ladder step.
func TestReleaseProber_LiftsAPreflightHoldOnceTheDomainRoutesHere(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("app.example.com", quarantinePreflight)
	require.True(t, q.IsQuarantined("app.example.com"))

	released := []string{}
	prober := testReleaseProber(q, releaseProberConfig{
		Released: func(domain string) { released = append(released, domain) },
	})

	prober.sweep()

	assert.False(t, q.IsQuarantined("app.example.com"))
	assert.Equal(t, []string{"app.example.com"}, released)
}

// An ACME rejection whose demonstrable cause was the domain pointing elsewhere
// deserves a retry once that is fixed — but the ladder history must survive,
// so a domain that flaps keeps climbing.
func TestReleaseProber_LiftsAnACMEHoldButKeepsTheLadder(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("app.example.com", quarantineACME)
	q.RecordFailure("app.example.com", quarantineACME)

	prober := testReleaseProber(q, releaseProberConfig{})
	prober.sweep()

	assert.False(t, q.IsQuarantined("app.example.com"))
	assert.Equal(t, 4*time.Hour, q.RecordFailure("app.example.com", quarantineACME),
		"the next failure is the third rung, not the first")
}

// A rate-limit hold is the CA's clock, not ours. The domain routing here again
// does nothing to lift Let's Encrypt's window, and ordering inside it both
// fails and pushes the window further out.
func TestReleaseProber_NeverLiftsARateLimitHold(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordRateLimited("app.example.com", time.Now().Add(2*time.Hour))

	recorder := newProbeRecorder()
	prober := testReleaseProber(q, releaseProberConfig{Preflight: recorder.probe})
	prober.sweep()

	assert.True(t, q.IsQuarantined("app.example.com"))
	assert.Empty(t, recorder.calls(), "no point probing a hold we may not lift")
}

func TestReleaseProber_LeavesAHoldAloneWhenTheProbeStillFails(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("app.example.com", quarantinePreflight)

	released := []string{}
	prober := testReleaseProber(q, releaseProberConfig{
		Preflight: newProbeRecorder("app.example.com").probe,
		Released:  func(domain string) { released = append(released, domain) },
	})
	prober.sweep()

	assert.True(t, q.IsQuarantined("app.example.com"))
	assert.Empty(t, released)
}

// A failing sweep must not escalate the ladder: the hold is already running,
// and counting every probe as a fresh failure would drive a domain to 24h
// within minutes.
func TestReleaseProber_FailedProbeDoesNotEscalateTheLadder(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("app.example.com", quarantinePreflight)

	prober := testReleaseProber(q, releaseProberConfig{
		Preflight: newProbeRecorder("app.example.com").probe,
	})
	prober.sweep()
	prober.sweep()
	prober.sweep()

	assert.Equal(t, 1, q.Snapshot()["app.example.com"].Failures)
}

func TestReleaseProber_SkipsDomainsTheProbeCannotSpeakFor(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("*.enode.site", quarantineACME)
	q.RecordFailure("dns.enode.site", quarantineACME)
	q.RecordFailure("http.example.com", quarantineACME)

	recorder := newProbeRecorder()
	prober := testReleaseProber(q, releaseProberConfig{
		Preflight:   recorder.probe,
		Unprobeable: func(domain string) bool { return domain == "dns.enode.site" },
	})
	prober.sweep()

	assert.Equal(t, []string{"http.example.com"}, recorder.calls(),
		"a wildcard has no name to answer on, and a DNS-01 zone need not route here")

	// The unprobed holds stay: nothing disproved them.
	assert.True(t, q.IsQuarantined("*.enode.site"))
	assert.True(t, q.IsQuarantined("dns.enode.site"))
	assert.False(t, q.IsQuarantined("http.example.com"))
}

func TestReleaseProber_IgnoresEntriesWhoseHoldHasAlreadyExpired(t *testing.T) {
	start := time.Now()
	q, current := testQuarantineAt(start)
	q.RecordFailure("app.example.com", quarantinePreflight)

	*current = start.Add(time.Hour)
	require.False(t, q.IsQuarantined("app.example.com"))

	recorder := newProbeRecorder()
	prober := testReleaseProber(q, releaseProberConfig{Preflight: recorder.probe})
	prober.sweep()

	assert.Empty(t, recorder.calls(), "nothing to release")
}

func TestReleaseProber_NotifiesChangeOnlyWhenSomethingWasReleased(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("app.example.com", quarantinePreflight)

	changes := 0
	prober := testReleaseProber(q, releaseProberConfig{
		Preflight: newProbeRecorder("app.example.com").probe,
		OnChange:  func() { changes++ },
	})
	prober.sweep()
	assert.Zero(t, changes)

	prober = testReleaseProber(q, releaseProberConfig{OnChange: func() { changes++ }})
	prober.sweep()
	assert.Equal(t, 1, changes)
}

// Zero means "operator said nothing", which must land on the default rather
// than silently disabling the feature; only an explicit negative turns it off.
func TestReleaseProbeInterval_MapsTheConfiguredValue(t *testing.T) {
	assert.Equal(t, DefaultReleaseProbeInterval, releaseProbeInterval(0))
	assert.Equal(t, 10*time.Second, releaseProbeInterval(10*time.Second))
	assert.Negative(t, releaseProbeInterval(-time.Second), "an explicit negative disables the loop")
}

func TestReleaseProber_ZeroIntervalDisablesTheLoop(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("app.example.com", quarantinePreflight)

	recorder := newProbeRecorder()
	prober := testReleaseProber(q, releaseProberConfig{Interval: 0, Preflight: recorder.probe})

	prober.Start()
	t.Cleanup(prober.Stop)
	time.Sleep(50 * time.Millisecond)

	assert.Empty(t, recorder.calls())
	assert.True(t, q.IsQuarantined("app.example.com"))
}

func TestReleaseProber_StartSweepsOnItsInterval(t *testing.T) {
	q, _ := testQuarantineAt(time.Now())
	q.RecordFailure("app.example.com", quarantinePreflight)

	prober := testReleaseProber(q, releaseProberConfig{Interval: 5 * time.Millisecond})
	prober.Start()
	t.Cleanup(prober.Stop)

	require.Eventually(t, func() bool {
		return !q.IsQuarantined("app.example.com")
	}, time.Second, 5*time.Millisecond)
}
