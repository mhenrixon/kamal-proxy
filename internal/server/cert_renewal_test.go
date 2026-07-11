package server

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRegistry builds a ready registry with no ACME clients, so renewal
// paths never touch the network.
func newTestRegistry(t *testing.T) *CertificateRegistry {
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

func TestNewCertificateRenewalManager_Defaults(t *testing.T) {
	registry := newTestRegistry(t)

	manager := NewCertificateRenewalManager(registry)

	assert.Equal(t, DefaultRenewalCheckInterval, manager.checkInterval)
	assert.Equal(t, DefaultRenewalThreshold, manager.renewalThreshold)
	assert.Same(t, registry, manager.registry)
}

func TestCertificateRenewalManager_StartStop(t *testing.T) {
	registry := newTestRegistry(t)
	manager := NewCertificateRenewalManager(registry)

	// A long interval keeps the ticker quiet; we only exercise the lifecycle.
	manager.checkInterval = time.Hour

	manager.Start()
	manager.Stop() // Must return promptly and not deadlock on the wait group.
}

func TestCertificateRenewalManager_FiresOnSchedule(t *testing.T) {
	registry := newTestRegistry(t)

	// A certificate already inside the renewal threshold.
	registry.certificates["test:example.com"] = &ManagedCertificate{
		Identifier: "test:example.com",
		Domains:    []string{"example.com"},
		NotAfter:   time.Now().Add(time.Hour), // well under the 30-day threshold
		Services:   map[string]bool{"service1": true},
	}

	var renewals int64
	done := make(chan struct{})
	var once sync.Once

	manager := NewCertificateRenewalManager(registry)
	manager.checkInterval = 10 * time.Millisecond
	manager.renewFn = func(cert *ManagedCertificate) error {
		if atomic.AddInt64(&renewals, 1) >= 2 {
			once.Do(func() { close(done) })
		}
		return nil
	}

	manager.Start()
	defer manager.Stop()

	select {
	case <-done:
		// Renewal fired on the initial check and again on the ticker.
	case <-time.After(2 * time.Second):
		t.Fatalf("renewal loop did not fire on schedule; got %d renewals", atomic.LoadInt64(&renewals))
	}

	assert.GreaterOrEqual(t, atomic.LoadInt64(&renewals), int64(2))
}

func TestCertificateRenewalManager_SkipsFreshCertificates(t *testing.T) {
	registry := newTestRegistry(t)

	// A certificate far outside the renewal threshold must never be renewed.
	registry.certificates["fresh:example.com"] = &ManagedCertificate{
		Identifier: "fresh:example.com",
		Domains:    []string{"example.com"},
		NotAfter:   time.Now().Add(60 * 24 * time.Hour),
		Services:   map[string]bool{"service1": true},
	}

	var renewals int64
	manager := NewCertificateRenewalManager(registry)
	manager.renewFn = func(cert *ManagedCertificate) error {
		atomic.AddInt64(&renewals, 1)
		return nil
	}

	// Drive one check directly rather than waiting on the ticker.
	manager.checkAndRenew()

	assert.Equal(t, int64(0), atomic.LoadInt64(&renewals))
}
