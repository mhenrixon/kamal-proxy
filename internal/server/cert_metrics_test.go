package server

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

// fakeTracker captures certificate metric emissions so tests can assert that
// the registry and renewal manager report them.
type fakeTracker struct {
	mu       sync.Mutex
	expiry   map[string]time.Time // domain -> expiry
	wildcard map[string]bool      // domain -> isWildcard
	renewals map[string]int       // "domain:success"/"domain:failure" -> count
	counts   []certCountSample

	cacheEvents     map[string]int // "service:result" -> count
	cacheRefusals   map[string]int // "service:reason" -> count
	cacheLeases     map[string]int // "service:outcome" -> count
	cacheLeaseWaits map[string]int // "service:outcome" -> count
	cacheEvictions  map[string]int // "service:state" -> count
}

type certCountSample struct {
	total, wildcard, http01 int
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{
		expiry:          make(map[string]time.Time),
		wildcard:        make(map[string]bool),
		renewals:        make(map[string]int),
		cacheEvents:     make(map[string]int),
		cacheRefusals:   make(map[string]int),
		cacheLeases:     make(map[string]int),
		cacheLeaseWaits: make(map[string]int),
		cacheEvictions:  make(map[string]int),
	}
}

func (f *fakeTracker) TrackRequest(service, method string, status int, dur time.Duration) {}
func (f *fakeTracker) AddInflightRequest(service string)                                  {}
func (f *fakeTracker) SubtractInflightRequest(service string)                             {}

func (f *fakeTracker) TrackCacheEvent(service, result string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheEvents[service+":"+result]++
}

func (f *fakeTracker) TrackCacheRefusal(service, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheRefusals[service+":"+reason]++
}

func (f *fakeTracker) TrackCacheLease(service, outcome string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheLeases[service+":"+outcome]++
}

func (f *fakeTracker) TrackCacheLeaseWait(service, outcome string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheLeaseWaits[service+":"+outcome]++
}

func (f *fakeTracker) TrackCacheEviction(service, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheEvictions[service+":"+state]++
}

func (f *fakeTracker) cacheEvictionCount(service, state string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cacheEvictions[service+":"+state]
}

func (f *fakeTracker) cacheLeaseCount(service, outcome string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cacheLeases[service+":"+outcome]
}

func (f *fakeTracker) cacheLeaseWaitCount(service, outcome string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cacheLeaseWaits[service+":"+outcome]
}

// cacheRefusalCount reports how many times a refusal reason was recorded.
func (f *fakeTracker) cacheRefusalCount(service, reason string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cacheRefusals[service+":"+reason]
}

// cacheRefusalsFor is every refusal recorded for a service, for diagnostics.
func (f *fakeTracker) cacheRefusalsFor(service string) map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	found := map[string]int{}
	for key, count := range f.cacheRefusals {
		if name, reason, ok := strings.Cut(key, ":"); ok && name == service {
			found[reason] = count
		}
	}
	return found
}

// cacheEventCount reports how many times a result was recorded for a service.
func (f *fakeTracker) cacheEventCount(service, result string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cacheEvents[service+":"+result]
}

func (f *fakeTracker) SetCertificateExpiry(domain string, isWildcard bool, expiryTime time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expiry[domain] = expiryTime
	f.wildcard[domain] = isWildcard
}

func (f *fakeTracker) IncCertificateRenewals(domain string, success bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := domain + ":failure"
	if success {
		key = domain + ":success"
	}
	f.renewals[key]++
}

func (f *fakeTracker) SetCertificateCount(total, wildcard, http01 int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts = append(f.counts, certCountSample{total, wildcard, http01})
}

func (f *fakeTracker) lastCount() (certCountSample, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.counts) == 0 {
		return certCountSample{}, false
	}
	return f.counts[len(f.counts)-1], true
}

func (f *fakeTracker) renewalCount(domain string, success bool) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := domain + ":failure"
	if success {
		key = domain + ":success"
	}
	return f.renewals[key]
}

// switchableTracker is installed into metrics.Tracker exactly once, before any
// test runs, and thereafter only its delegate changes.
//
// Swapping metrics.Tracker itself is a data race: it is a package-level variable
// that every request path reads, and background work outlives the test that
// started it -- a stale revalidation goroutine reading the tracker while the
// next test installs its own is a genuine concurrent write. Swapping an atomic
// delegate instead removes the write entirely.
type switchableTracker struct {
	delegate atomic.Pointer[fakeTracker]
}

var activeTracker = &switchableTracker{}

func init() {
	// In init rather than in installFakeTracker: at this point no goroutine
	// exists that could be reading the variable.
	metrics.Tracker = activeTracker
}

func (s *switchableTracker) current() *fakeTracker { return s.delegate.Load() }

func (s *switchableTracker) TrackRequest(service, method string, status int, dur time.Duration) {}
func (s *switchableTracker) AddInflightRequest(service string)                                  {}
func (s *switchableTracker) SubtractInflightRequest(service string)                             {}

func (s *switchableTracker) SetCertificateExpiry(domain string, isWildcard bool, expiry time.Time) {
	if fake := s.current(); fake != nil {
		fake.SetCertificateExpiry(domain, isWildcard, expiry)
	}
}

func (s *switchableTracker) IncCertificateRenewals(domain string, success bool) {
	if fake := s.current(); fake != nil {
		fake.IncCertificateRenewals(domain, success)
	}
}

func (s *switchableTracker) SetCertificateCount(total, wildcard, http01 int) {
	if fake := s.current(); fake != nil {
		fake.SetCertificateCount(total, wildcard, http01)
	}
}

func (s *switchableTracker) TrackCacheEvent(service, result string) {
	if fake := s.current(); fake != nil {
		fake.TrackCacheEvent(service, result)
	}
}

func (s *switchableTracker) TrackCacheRefusal(service, reason string) {
	if fake := s.current(); fake != nil {
		fake.TrackCacheRefusal(service, reason)
	}
}

func (s *switchableTracker) TrackCacheLease(service, outcome string) {
	if fake := s.current(); fake != nil {
		fake.TrackCacheLease(service, outcome)
	}
}

func (s *switchableTracker) TrackCacheLeaseWait(service, outcome string) {
	if fake := s.current(); fake != nil {
		fake.TrackCacheLeaseWait(service, outcome)
	}
}

func (s *switchableTracker) TrackCacheEviction(service, state string) {
	if fake := s.current(); fake != nil {
		fake.TrackCacheEviction(service, state)
	}
}

// installFakeTracker points the tracker at a fresh capturing tracker for the
// duration of one test.
func installFakeTracker(t *testing.T) *fakeTracker {
	t.Helper()

	fake := newFakeTracker()
	previous := activeTracker.delegate.Swap(fake)
	t.Cleanup(func() { activeTracker.delegate.Store(previous) })

	return fake
}

// The certificate gauges used to be published by the deleted registry, which
// tracked its own wildcard/HTTP-01 split. The surviving renewer is now the only
// reporter, so these pin that the same gauges still move.
func TestCertRenewer_ReportsCertificateGauges(t *testing.T) {
	fake := installFakeTracker(t)
	manager := testSANCertManager(t)

	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)
	manager.SetDynamicDomains("service1", []string{"app.example.com", "b.example.com", "app.other.com"})
	adoptTestCert(t, manager, []string{"*.example.com"}, notBefore, notAfter)
	adoptTestCert(t, manager, []string{"app.other.com"}, notBefore, notAfter)

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: successfulObtainer(t)})
	renewer.reconcile()

	count, ok := fake.lastCount()
	require.True(t, ok, "expected a certificate count sample")
	assert.Equal(t, 2, count.total)
	assert.Equal(t, 1, count.wildcard)
	assert.Equal(t, 1, count.http01)

	assert.Equal(t, notAfter.Unix(), fake.expiry["*.example.com"].Unix())
	assert.True(t, fake.wildcard["*.example.com"])
	assert.Equal(t, notAfter.Unix(), fake.expiry["app.other.com"].Unix())
	assert.False(t, fake.wildcard["app.other.com"])
}

func TestCertRenewer_EmitsRenewalSuccess(t *testing.T) {
	fake := installFakeTracker(t)
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com"})
	adoptTestCert(t, manager, []string{"a.example.com", "b.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: successfulObtainer(t)})
	renewer.reconcile()

	assert.Equal(t, 1, fake.renewalCount("a.example.com", true))
	assert.Equal(t, 1, fake.renewalCount("b.example.com", true))
	assert.Equal(t, 0, fake.renewalCount("a.example.com", false))

	count, ok := fake.lastCount()
	require.True(t, ok, "a reconcile pass should refresh the certificate count")
	assert.Equal(t, 1, count.total)
}

func TestCertRenewer_EmitsRenewalFailure(t *testing.T) {
	fake := installFakeTracker(t)
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"a.example.com", "b.example.com"})
	adoptTestCert(t, manager, []string{"a.example.com", "b.example.com"},
		time.Now().Add(-70*24*time.Hour), time.Now().Add(20*24*time.Hour))

	failing := &fakeObtainer{respond: func(certificate.ObtainRequest) (*certificate.Resource, error) {
		return nil, assert.AnError
	}}
	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: failing})
	renewer.reconcile()

	assert.Equal(t, 1, fake.renewalCount("a.example.com", false))
	assert.Equal(t, 1, fake.renewalCount("b.example.com", false))
	assert.Equal(t, 0, fake.renewalCount("a.example.com", true))
}

func TestCertRenewer_SkipsRenewalMetricsForFreshCerts(t *testing.T) {
	fake := installFakeTracker(t)
	manager := testSANCertManager(t)

	manager.SetDynamicDomains("service1", []string{"a.example.com"})
	adoptTestCert(t, manager, []string{"a.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))

	renewer := newCertRenewer(manager, newDomainQuarantine(), certRenewerConfig{Obtainer: successfulObtainer(t)})
	renewer.reconcile()

	assert.Equal(t, 0, fake.renewalCount("a.example.com", true))
	assert.Equal(t, 0, fake.renewalCount("a.example.com", false))

	// The count gauge still refreshes even when nothing needs renewal.
	count, ok := fake.lastCount()
	require.True(t, ok)
	assert.Equal(t, 1, count.total)
}
