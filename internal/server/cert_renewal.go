package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

const (
	// DefaultRenewalCheckInterval is how often to check for expiring certificates
	DefaultRenewalCheckInterval = 12 * time.Hour

	// DefaultRenewalThreshold is how long before expiry to renew
	DefaultRenewalThreshold = 30 * 24 * time.Hour // 30 days
)

// CertificateRenewalManager handles background certificate renewal
type CertificateRenewalManager struct {
	registry         *CertificateRegistry
	checkInterval    time.Duration
	renewalThreshold time.Duration

	// renewFn performs the actual renewal of a single certificate. It defaults
	// to renewCertificate and exists as a seam so tests can observe scheduling
	// without touching the network.
	renewFn func(*ManagedCertificate) error

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewCertificateRenewalManager creates a new renewal manager
func NewCertificateRenewalManager(registry *CertificateRegistry) *CertificateRenewalManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &CertificateRenewalManager{
		registry:         registry,
		checkInterval:    DefaultRenewalCheckInterval,
		renewalThreshold: DefaultRenewalThreshold,
		ctx:              ctx,
		cancel:           cancel,
	}
	m.renewFn = m.renewCertificate
	return m
}

// Start begins the background renewal loop
func (m *CertificateRenewalManager) Start() {
	m.wg.Add(1)
	go m.renewalLoop()
	slog.Info("Certificate renewal manager started",
		"check_interval", m.checkInterval,
		"renewal_threshold", m.renewalThreshold,
	)
}

// Stop gracefully stops the renewal manager
func (m *CertificateRenewalManager) Stop() {
	m.cancel()
	m.wg.Wait()
	slog.Info("Certificate renewal manager stopped")
}

func (m *CertificateRenewalManager) renewalLoop() {
	defer m.wg.Done()

	// Do an initial check on startup
	m.checkAndRenew()

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndRenew()
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *CertificateRenewalManager) checkAndRenew() {
	m.registry.mu.RLock()
	certsToRenew := make([]*ManagedCertificate, 0)
	now := time.Now()

	for _, cert := range m.registry.certificates {
		timeUntilExpiry := time.Until(cert.NotAfter)
		if timeUntilExpiry < m.renewalThreshold {
			certsToRenew = append(certsToRenew, cert)
			slog.Info("Certificate needs renewal",
				"identifier", cert.Identifier,
				"domains", cert.Domains,
				"expires_in", timeUntilExpiry,
			)
		}
	}
	m.registry.mu.RUnlock()

	if len(certsToRenew) == 0 {
		slog.Debug("No certificates need renewal", "checked_at", now)
		return
	}

	slog.Info("Renewing certificates", "count", len(certsToRenew))

	for _, cert := range certsToRenew {
		if err := m.renewFn(cert); err != nil {
			slog.Error("Failed to renew certificate",
				"identifier", cert.Identifier,
				"domains", cert.Domains,
				"error", err,
			)
		}
	}
}

func (m *CertificateRenewalManager) renewCertificate(cert *ManagedCertificate) error {
	// For DNS-01 certificates, use the solver
	if m.registry.dnsSolver != nil && cert.Resource != nil {
		result := &acme.CertificateResult{
			Domains:    cert.Domains,
			IsWildcard: cert.IsWildcard,
			Resource:   cert.Resource,
		}

		newResult, err := m.registry.dnsSolver.RenewCertificate(m.ctx, result)
		if err != nil {
			return err
		}

		// Update the certificate in the registry
		m.registry.mu.Lock()
		cert.Certificate = newResult.Certificate
		cert.NotAfter = newResult.NotAfter
		cert.Resource = newResult.Resource
		m.registry.mu.Unlock()

		// Persist state
		if err := m.registry.saveState(); err != nil {
			slog.Warn("Failed to save state after renewal", "error", err)
		}

		slog.Info("Certificate renewed successfully",
			"identifier", cert.Identifier,
			"domains", cert.Domains,
			"new_expiry", newResult.NotAfter,
		)
		return nil
	}

	// For HTTP-01 certificates, trigger a new request
	if m.registry.httpFallback != nil && len(cert.Domains) > 0 {
		// The autocert manager handles renewal automatically
		// We just need to trigger a certificate request
		slog.Debug("HTTP-01 certificate will be renewed on next request",
			"identifier", cert.Identifier,
		)
		return nil
	}

	return nil
}
