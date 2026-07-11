package server

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/basecamp/kamal-proxy/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTracker captures certificate metric emissions so tests can assert that
// the registry and renewal manager report them.
type fakeTracker struct {
	mu       sync.Mutex
	expiry   map[string]time.Time // domain -> expiry
	wildcard map[string]bool      // domain -> isWildcard
	renewals map[string]int       // "domain:success"/"domain:failure" -> count
	counts   []certCountSample
}

type certCountSample struct {
	total, wildcard, http01 int
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{
		expiry:   make(map[string]time.Time),
		wildcard: make(map[string]bool),
		renewals: make(map[string]int),
	}
}

func (f *fakeTracker) TrackRequest(service, method string, status int, dur time.Duration) {}
func (f *fakeTracker) AddInflightRequest(service string)                                  {}
func (f *fakeTracker) SubtractInflightRequest(service string)                             {}

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

// installFakeTracker swaps in a capturing tracker and restores the previous one
// when the test ends.
func installFakeTracker(t *testing.T) *fakeTracker {
	t.Helper()
	prev := metrics.Tracker
	fake := newFakeTracker()
	metrics.Tracker = fake
	t.Cleanup(func() { metrics.Tracker = prev })
	return fake
}

func metricsTestRegistry(t *testing.T) *CertificateRegistry {
	t.Helper()
	tmpDir := t.TempDir()
	registry, err := NewCertificateRegistry(CertificateRegistryConfig{
		CachePath: filepath.Join(tmpDir, "certs"),
		StatePath: filepath.Join(tmpDir, "certificates.state"),
	})
	require.NoError(t, err)
	registry.ready = true
	return registry
}

func TestCertificateRegistry_ReportCertificateMetrics(t *testing.T) {
	fake := installFakeTracker(t)
	registry := metricsTestRegistry(t)

	expiry := time.Now().Add(60 * 24 * time.Hour)
	registry.certificates["wildcard:example.com"] = &ManagedCertificate{
		Identifier: "wildcard:example.com",
		Domains:    []string{"*.example.com"},
		IsWildcard: true,
		NotAfter:   expiry,
		Services:   map[string]bool{},
	}
	registry.certificates["http01:app.other.com"] = &ManagedCertificate{
		Identifier: "http01:app.other.com",
		Domains:    []string{"app.other.com"},
		IsWildcard: false,
		NotAfter:   expiry,
		Services:   map[string]bool{},
	}

	registry.reportCertificateMetrics()

	count, ok := fake.lastCount()
	require.True(t, ok, "expected a certificate count sample")
	assert.Equal(t, 2, count.total)
	assert.Equal(t, 1, count.wildcard)
	assert.Equal(t, 1, count.http01)

	assert.Equal(t, expiry.Unix(), fake.expiry["*.example.com"].Unix())
	assert.True(t, fake.wildcard["*.example.com"])
	assert.Equal(t, expiry.Unix(), fake.expiry["app.other.com"].Unix())
	assert.False(t, fake.wildcard["app.other.com"])
}

func TestCertificateRenewalManager_EmitsRenewalSuccess(t *testing.T) {
	fake := installFakeTracker(t)
	registry := metricsTestRegistry(t)

	// A cert inside the renewal threshold with a renewFn that succeeds.
	registry.certificates["dns:example.com"] = &ManagedCertificate{
		Identifier: "dns:example.com",
		Domains:    []string{"a.example.com", "b.example.com"},
		NotAfter:   time.Now().Add(time.Hour),
		Services:   map[string]bool{},
	}

	manager := NewCertificateRenewalManager(registry)
	manager.renewFn = func(c *ManagedCertificate) error { return nil }

	manager.checkAndRenew()

	assert.Equal(t, 1, fake.renewalCount("a.example.com", true))
	assert.Equal(t, 1, fake.renewalCount("b.example.com", true))
	assert.Equal(t, 0, fake.renewalCount("a.example.com", false))

	// The count gauge is refreshed on every check pass.
	count, ok := fake.lastCount()
	require.True(t, ok, "checkAndRenew should refresh the certificate count")
	assert.Equal(t, 1, count.total)
}

func TestCertificateRenewalManager_EmitsRenewalFailure(t *testing.T) {
	fake := installFakeTracker(t)
	registry := metricsTestRegistry(t)

	registry.certificates["dns:example.com"] = &ManagedCertificate{
		Identifier: "dns:example.com",
		Domains:    []string{"a.example.com", "b.example.com"},
		NotAfter:   time.Now().Add(time.Hour),
		Services:   map[string]bool{},
	}

	manager := NewCertificateRenewalManager(registry)
	manager.renewFn = func(c *ManagedCertificate) error { return assert.AnError }

	manager.checkAndRenew()

	assert.Equal(t, 1, fake.renewalCount("a.example.com", false))
	assert.Equal(t, 1, fake.renewalCount("b.example.com", false))
	assert.Equal(t, 0, fake.renewalCount("a.example.com", true))
}

func TestCertificateRenewalManager_SkipsRenewalMetricsForFreshCerts(t *testing.T) {
	fake := installFakeTracker(t)
	registry := metricsTestRegistry(t)

	// A cert well outside the threshold: no renewal, so no renewal metric.
	registry.certificates["dns:example.com"] = &ManagedCertificate{
		Identifier: "dns:example.com",
		Domains:    []string{"a.example.com"},
		NotAfter:   time.Now().Add(60 * 24 * time.Hour),
		Services:   map[string]bool{},
	}

	manager := NewCertificateRenewalManager(registry)
	manager.renewFn = func(c *ManagedCertificate) error { return nil }

	manager.checkAndRenew()

	assert.Equal(t, 0, fake.renewalCount("a.example.com", true))
	assert.Equal(t, 0, fake.renewalCount("a.example.com", false))

	// The count gauge still refreshes even when nothing needs renewal.
	count, ok := fake.lastCount()
	require.True(t, ok)
	assert.Equal(t, 1, count.total)
}
