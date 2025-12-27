package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
)

var (
	ErrCertificatePending     = errors.New("certificate is being provisioned")
	ErrCertificateNotFound    = errors.New("certificate not found")
	ErrProvisioningFailed     = errors.New("certificate provisioning failed")
	ErrProvisioningInProgress = errors.New("certificate provisioning already in progress")
)

// CertificateResult holds the result of a certificate provisioning operation
type CertificateResult struct {
	Certificate *tls.Certificate
	Resource    *certificate.Resource
	Domains     []string
	NotAfter    time.Time
	IsWildcard  bool
	Error       error
}

// ProvisioningState tracks the state of certificate provisioning
type ProvisioningState int

const (
	StateIdle ProvisioningState = iota
	StateProvisioning
	StateComplete
	StateFailed
)

// CertificateSolver handles certificate provisioning with DNS-01 challenges
type CertificateSolver struct {
	mu          sync.RWMutex
	acmeClient  *ACMEClient
	dnsProvider challenge.Provider
	registered  bool

	// Provisioning state per domain group
	provisioning map[string]*provisioningJob
}

type provisioningJob struct {
	domains   []string
	state     ProvisioningState
	result    *CertificateResult
	startedAt time.Time
	done      chan struct{}
}

// NewCertificateSolver creates a new certificate solver
func NewCertificateSolver(config ACMEConfig, dnsProvider challenge.Provider) (*CertificateSolver, error) {
	client, err := NewACMEClient(config)
	if err != nil {
		return nil, err
	}

	if err := client.SetDNSProvider(dnsProvider); err != nil {
		return nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	return &CertificateSolver{
		acmeClient:   client,
		dnsProvider:  dnsProvider,
		provisioning: make(map[string]*provisioningJob),
	}, nil
}

// EnsureRegistered ensures the ACME account is registered
func (s *CertificateSolver) EnsureRegistered(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.registered {
		return nil
	}

	if err := s.acmeClient.Register(ctx); err != nil {
		return err
	}

	s.registered = true
	return nil
}

// ProvisionCertificate provisions a certificate for the given domains
// It returns immediately if provisioning is already in progress
func (s *CertificateSolver) ProvisionCertificate(ctx context.Context, domains []string) (*CertificateResult, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains provided")
	}

	// Use the first domain as the job key (primary domain)
	jobKey := domains[0]

	s.mu.Lock()
	job, exists := s.provisioning[jobKey]

	if exists {
		switch job.state {
		case StateProvisioning:
			s.mu.Unlock()
			return nil, ErrProvisioningInProgress
		case StateComplete:
			result := job.result
			s.mu.Unlock()
			return result, nil
		case StateFailed:
			result := job.result
			s.mu.Unlock()
			return nil, result.Error
		}
	}

	// Create new provisioning job
	job = &provisioningJob{
		domains:   domains,
		state:     StateProvisioning,
		startedAt: time.Now(),
		done:      make(chan struct{}),
	}
	s.provisioning[jobKey] = job
	s.mu.Unlock()

	// Ensure registered before provisioning
	if err := s.EnsureRegistered(ctx); err != nil {
		s.failJob(jobKey, err)
		return nil, err
	}

	// Start provisioning in background
	go s.doProvision(ctx, jobKey, job)

	return nil, ErrCertificatePending
}

// WaitForCertificate waits for a certificate to be provisioned
func (s *CertificateSolver) WaitForCertificate(ctx context.Context, domains []string, timeout time.Duration) (*CertificateResult, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains provided")
	}

	jobKey := domains[0]

	// First try to provision (or get existing)
	result, err := s.ProvisionCertificate(ctx, domains)
	if err == nil {
		return result, nil
	}
	if !errors.Is(err, ErrProvisioningInProgress) && !errors.Is(err, ErrCertificatePending) {
		return nil, err
	}

	// Wait for provisioning to complete
	s.mu.RLock()
	job, exists := s.provisioning[jobKey]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrCertificateNotFound
	}

	select {
	case <-job.done:
		s.mu.RLock()
		result := job.result
		s.mu.RUnlock()

		if result.Error != nil {
			return nil, result.Error
		}
		return result, nil

	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for certificate provisioning")

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GetProvisioningState returns the current provisioning state for domains
func (s *CertificateSolver) GetProvisioningState(domains []string) (ProvisioningState, error) {
	if len(domains) == 0 {
		return StateIdle, fmt.Errorf("no domains provided")
	}

	jobKey := domains[0]

	s.mu.RLock()
	defer s.mu.RUnlock()

	job, exists := s.provisioning[jobKey]
	if !exists {
		return StateIdle, nil
	}

	return job.state, nil
}

// ClearProvisioningState clears the provisioning state for domains
func (s *CertificateSolver) ClearProvisioningState(domains []string) {
	if len(domains) == 0 {
		return
	}

	jobKey := domains[0]

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.provisioning, jobKey)
}

func (s *CertificateSolver) doProvision(ctx context.Context, jobKey string, job *provisioningJob) {
	defer close(job.done)

	slog.Info("Starting certificate provisioning", "domains", job.domains)

	cert, err := s.acmeClient.ObtainCertificate(ctx, job.domains)
	if err != nil {
		slog.Error("Certificate provisioning failed", "domains", job.domains, "error", err)
		s.failJob(jobKey, err)
		return
	}

	// Parse the certificate
	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		slog.Error("Failed to parse certificate", "domains", job.domains, "error", err)
		s.failJob(jobKey, fmt.Errorf("failed to parse certificate: %w", err))
		return
	}

	// Get expiration from parsed cert
	var notAfter time.Time
	if tlsCert.Leaf != nil {
		notAfter = tlsCert.Leaf.NotAfter
	}

	// Check if this is a wildcard certificate
	isWildcard := false
	for _, d := range job.domains {
		if len(d) > 0 && d[0] == '*' {
			isWildcard = true
			break
		}
	}

	result := &CertificateResult{
		Certificate: &tlsCert,
		Resource:    cert,
		Domains:     job.domains,
		NotAfter:    notAfter,
		IsWildcard:  isWildcard,
	}

	s.mu.Lock()
	job.state = StateComplete
	job.result = result
	s.mu.Unlock()

	slog.Info("Certificate provisioned successfully",
		"domains", job.domains,
		"isWildcard", isWildcard,
		"expiresAt", notAfter,
	)
}

func (s *CertificateSolver) failJob(jobKey string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, exists := s.provisioning[jobKey]
	if !exists {
		return
	}

	job.state = StateFailed
	job.result = &CertificateResult{
		Domains: job.domains,
		Error:   fmt.Errorf("%w: %v", ErrProvisioningFailed, err),
	}
}

// RenewCertificate renews an existing certificate
func (s *CertificateSolver) RenewCertificate(ctx context.Context, result *CertificateResult) (*CertificateResult, error) {
	if result.Resource == nil {
		return nil, fmt.Errorf("no certificate resource to renew")
	}

	if err := s.EnsureRegistered(ctx); err != nil {
		return nil, err
	}

	cert, err := s.acmeClient.RenewCertificate(ctx, result.Resource)
	if err != nil {
		return nil, err
	}

	// Parse the renewed certificate
	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	var notAfter time.Time
	if tlsCert.Leaf != nil {
		notAfter = tlsCert.Leaf.NotAfter
	}

	return &CertificateResult{
		Certificate: &tlsCert,
		Resource:    cert,
		Domains:     result.Domains,
		NotAfter:    notAfter,
		IsWildcard:  result.IsWildcard,
	}, nil
}
