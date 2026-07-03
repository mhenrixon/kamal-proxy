package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/basecamp/kamal-proxy/internal/server/acme/providers"
	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrCertificatePending  = errors.New("certificate is being provisioned")
	ErrCertificateNotFound = errors.New("certificate not found for domain")
	ErrRegistryNotReady    = errors.New("certificate registry not ready")
)

// ManagedCertificate represents a certificate managed by the registry
type ManagedCertificate struct {
	Identifier  string                `json:"identifier"`
	Domains     []string              `json:"domains"`
	IsWildcard  bool                  `json:"is_wildcard"`
	NotAfter    time.Time             `json:"not_after"`
	Services    map[string]bool       `json:"services"` // Services using this cert
	Certificate *tls.Certificate      `json:"-"`        // Not persisted
	Resource    *certificate.Resource `json:"-"`        // Not persisted
}

// CertificateRegistryConfig holds configuration for the certificate registry
type CertificateRegistryConfig struct {
	// ACME configuration
	Email          string
	Directory      string
	DNSProvider    acme.ProviderName
	PreferWildcard bool

	// Paths
	CachePath string
	StatePath string

	// HTTP-01 fallback
	HTTPFallback bool
}

// CertificateRegistry manages certificates centrally across all services
type CertificateRegistry struct {
	mu     sync.RWMutex
	config CertificateRegistryConfig

	// Certificate storage
	certificates map[string]*ManagedCertificate // key: certificate identifier
	domainToCert map[string]string              // domain -> certificate identifier

	// Pending domains waiting to be batched (domain -> service)
	pendingDomains map[string]string

	// Domain grouper for analyzing domains
	grouper *DomainGrouper

	// ACME clients
	dnsSolver    *acme.CertificateSolver
	httpFallback *autocert.Manager

	// Provisioning state - keyed by root domain for batching
	provisioning map[string]chan struct{} // rootDomain -> done channel

	// State
	ready bool
}

// NewCertificateRegistry creates a new certificate registry
func NewCertificateRegistry(config CertificateRegistryConfig) (*CertificateRegistry, error) {
	registry := &CertificateRegistry{
		config:         config,
		certificates:   make(map[string]*ManagedCertificate),
		domainToCert:   make(map[string]string),
		pendingDomains: make(map[string]string),
		grouper:        NewDomainGrouper(),
		provisioning:   make(map[string]chan struct{}),
	}

	// Configure the domain grouper
	registry.grouper.PreferWildcard = config.PreferWildcard

	// Ensure cache directory exists
	if config.CachePath != "" {
		if err := os.MkdirAll(config.CachePath, 0700); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	return registry, nil
}

// Initialize sets up the registry with DNS provider and loads state
func (r *CertificateRegistry) Initialize(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Set up DNS provider if configured
	if r.config.DNSProvider != "" && r.config.DNSProvider != "none" {
		dnsProvider, err := providers.NewProvider(r.config.DNSProvider)
		if err != nil {
			if r.config.HTTPFallback {
				slog.Warn("DNS provider not available, falling back to HTTP-01",
					"provider", r.config.DNSProvider,
					"error", err,
				)
			} else {
				return fmt.Errorf("failed to create DNS provider: %w", err)
			}
		} else {
			acmeConfig := acme.ACMEConfig{
				Email:          r.config.Email,
				Directory:      r.config.Directory,
				DNSProvider:    r.config.DNSProvider,
				PreferWildcard: r.config.PreferWildcard,
			}

			solver, err := acme.NewCertificateSolver(acmeConfig, dnsProvider)
			if err != nil {
				return fmt.Errorf("failed to create certificate solver: %w", err)
			}
			r.dnsSolver = solver
			r.grouper.DNSProviderAvailable = true

			slog.Info("DNS-01 challenge solver initialized",
				"provider", r.config.DNSProvider,
			)
		}
	}

	// Set up HTTP-01 fallback
	if r.config.HTTPFallback || r.dnsSolver == nil {
		r.httpFallback = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(r.config.CachePath, "http01")),
		}
		slog.Info("HTTP-01 challenge fallback initialized")
	}

	// Load persisted state
	if err := r.loadState(); err != nil {
		slog.Warn("Failed to load certificate state", "error", err)
		// Continue anyway - we'll reprovision certificates
	}

	r.ready = true
	return nil
}

// RegisterDomain registers a domain for certificate management
func (r *CertificateRegistry) RegisterDomain(domain string, service string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.ready {
		return ErrRegistryNotReady
	}

	// Check if domain already has a certificate
	if certID, ok := r.domainToCert[domain]; ok {
		cert := r.certificates[certID]
		if cert != nil {
			cert.Services[service] = true
			slog.Debug("Domain already registered",
				"domain", domain,
				"certificate", certID,
				"service", service,
			)
			return nil
		}
	}

	// Check if a wildcard certificate already covers this domain
	for _, cert := range r.certificates {
		if cert.IsWildcard {
			for _, d := range cert.Domains {
				if matchesWildcard(d, domain) {
					cert.Services[service] = true
					r.domainToCert[domain] = cert.Identifier
					slog.Debug("Domain covered by existing wildcard",
						"domain", domain,
						"wildcard", d,
						"service", service,
					)
					return nil
				}
			}
		}
	}

	// Add to pending domains for batched provisioning
	r.pendingDomains[domain] = service
	slog.Debug("Domain added to pending batch",
		"domain", domain,
		"service", service,
		"pending_count", len(r.pendingDomains),
	)

	return nil
}

// UnregisterDomain removes a domain from certificate management for a service
func (r *CertificateRegistry) UnregisterDomain(domain string, service string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	certID, ok := r.domainToCert[domain]
	if !ok {
		return nil
	}

	cert := r.certificates[certID]
	if cert == nil {
		return nil
	}

	delete(cert.Services, service)

	// If no services are using this cert, we can clean it up later
	if len(cert.Services) == 0 {
		slog.Info("Certificate no longer used by any service",
			"identifier", certID,
			"domains", cert.Domains,
		)
	}

	return nil
}

// GetCertificate returns a certificate for the given TLS client hello
func (r *CertificateRegistry) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		return nil, fmt.Errorf("no server name provided")
	}

	r.mu.RLock()
	ready := r.ready
	certID, hasCert := r.domainToCert[domain]
	var cert *ManagedCertificate
	if hasCert {
		cert = r.certificates[certID]
	}
	r.mu.RUnlock()

	if !ready {
		return nil, ErrRegistryNotReady
	}

	// Check if we have a valid certificate
	if cert != nil && cert.Certificate != nil {
		// Check if certificate is still valid (not expiring within 24 hours)
		if time.Until(cert.NotAfter) > 24*time.Hour {
			return cert.Certificate, nil
		}
		slog.Info("Certificate expiring soon, will reprovision",
			"domain", domain,
			"expiresAt", cert.NotAfter,
		)
	}

	// Check for wildcard certificate that might cover this domain
	wildcardCert := r.findWildcardCert(domain)
	if wildcardCert != nil && wildcardCert.Certificate != nil {
		return wildcardCert.Certificate, nil
	}

	// Need to provision certificate
	return r.provisionCertificate(hello.Context(), domain)
}

// findWildcardCert looks for a wildcard certificate that covers the domain
func (r *CertificateRegistry) findWildcardCert(domain string) *ManagedCertificate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, cert := range r.certificates {
		if !cert.IsWildcard {
			continue
		}
		for _, d := range cert.Domains {
			if matchesWildcard(d, domain) {
				return cert
			}
		}
	}
	return nil
}

// matchesWildcard checks if a wildcard pattern matches a domain
func matchesWildcard(pattern, domain string) bool {
	if len(pattern) < 3 || pattern[0] != '*' || pattern[1] != '.' {
		return false
	}

	suffix := pattern[1:] // ".example.com"
	if len(domain) <= len(suffix) {
		return false
	}

	// Check if domain ends with the suffix
	if domain[len(domain)-len(suffix):] != suffix {
		return false
	}

	// Check that the prefix (subdomain) doesn't contain dots (single level only)
	prefix := domain[:len(domain)-len(suffix)]
	for _, c := range prefix {
		if c == '.' {
			return false
		}
	}

	return true
}

// provisionCertificate provisions a certificate for a domain
// It batches together all pending domains from the same root domain
func (r *CertificateRegistry) provisionCertificate(ctx context.Context, domain string) (*tls.Certificate, error) {
	// Get root domain for batching
	rootDomain, err := getRootDomain(domain)
	if err != nil {
		rootDomain = domain // Fall back to domain itself
	}

	// Check if already provisioning for this root domain
	r.mu.Lock()
	if done, ok := r.provisioning[rootDomain]; ok {
		r.mu.Unlock()
		// Wait for existing provisioning to complete
		select {
		case <-done:
			return r.getCertificateForDomain(domain)
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, ErrCertificatePending
		}
	}

	// Collect ALL pending domains that share the same root domain
	domainsToProvision := []string{domain}
	for pendingDomain := range r.pendingDomains {
		pendingRoot, _ := getRootDomain(pendingDomain)
		if pendingRoot == rootDomain && pendingDomain != domain {
			domainsToProvision = append(domainsToProvision, pendingDomain)
		}
	}

	// Start provisioning
	done := make(chan struct{})
	r.provisioning[rootDomain] = done

	// Remove all domains we're about to provision from pending
	for _, d := range domainsToProvision {
		delete(r.pendingDomains, d)
	}
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.provisioning, rootDomain)
		close(done)
		r.mu.Unlock()
	}()

	slog.Info("Batching domains for certificate provisioning",
		"requested_domain", domain,
		"root_domain", rootDomain,
		"batch_size", len(domainsToProvision),
		"domains", domainsToProvision,
	)

	// Analyze ALL domains together to determine optimal strategy
	analysis := r.grouper.AnalyzeDomains(domainsToProvision)

	if len(analysis.Groups) == 0 {
		return nil, fmt.Errorf("failed to analyze domains: %v", domainsToProvision)
	}

	// Find the group containing our requested domain
	var targetGroup *DomainGroup
	for _, group := range analysis.Groups {
		if group.RootDomain == rootDomain {
			targetGroup = group
			break
		}
	}

	if targetGroup == nil {
		targetGroup = analysis.Groups[0]
	}

	slog.Info("Certificate strategy determined",
		"strategy", targetGroup.Strategy.String(),
		"root_domain", targetGroup.RootDomain,
		"subdomains", targetGroup.Subdomains,
		"includes_apex", targetGroup.IncludesApex,
	)

	// Try DNS-01 for wildcards, fall back to HTTP-01
	if targetGroup.Strategy == StrategyWildcard && r.dnsSolver != nil {
		return r.provisionWithDNS(ctx, targetGroup)
	}

	// For SAN strategy with DNS provider, batch them together
	if targetGroup.Strategy == StrategySAN && r.dnsSolver != nil && len(domainsToProvision) > 1 {
		return r.provisionWithDNS(ctx, targetGroup)
	}

	// Use HTTP-01 fallback for individual certificates
	if r.httpFallback != nil {
		return r.provisionWithHTTP(ctx, domain)
	}

	return nil, fmt.Errorf("no certificate provisioning method available for %s", domain)
}

// getRootDomain extracts the registrable domain (e.g., "example.com" from "app.example.com")
func getRootDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

// provisionWithDNS provisions a certificate using DNS-01 challenge
func (r *CertificateRegistry) provisionWithDNS(ctx context.Context, group *DomainGroup) (*tls.Certificate, error) {
	domains := group.GetDomainsForCert()

	slog.Info("Provisioning certificate with DNS-01",
		"domains", domains,
		"strategy", group.Strategy.String(),
	)

	result, err := r.dnsSolver.WaitForCertificate(ctx, domains, 5*time.Minute)
	if err != nil {
		return nil, err
	}

	// Store the certificate
	managed := &ManagedCertificate{
		Identifier:  group.CertificateIdentifier(),
		Domains:     domains,
		IsWildcard:  group.Strategy == StrategyWildcard,
		NotAfter:    result.NotAfter,
		Services:    make(map[string]bool),
		Certificate: result.Certificate,
		Resource:    result.Resource,
	}

	r.mu.Lock()
	r.certificates[managed.Identifier] = managed
	for _, d := range domains {
		r.domainToCert[d] = managed.Identifier
	}
	// Also map subdomains for wildcard
	if managed.IsWildcard {
		for _, d := range group.FullDomains {
			r.domainToCert[d] = managed.Identifier
		}
	}
	r.mu.Unlock()

	// Persist state
	if err := r.saveState(); err != nil {
		slog.Warn("Failed to save certificate state", "error", err)
	}

	return result.Certificate, nil
}

// provisionWithHTTP provisions a certificate using HTTP-01 challenge
func (r *CertificateRegistry) provisionWithHTTP(ctx context.Context, domain string) (*tls.Certificate, error) {
	if r.httpFallback == nil {
		return nil, fmt.Errorf("HTTP-01 fallback not available")
	}

	slog.Info("Provisioning certificate with HTTP-01", "domain", domain)

	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	cert, err := r.httpFallback.GetCertificate(hello)
	if err != nil {
		return nil, fmt.Errorf("HTTP-01 provisioning failed: %w", err)
	}

	// Store reference
	managed := &ManagedCertificate{
		Identifier:  "http01:" + domain,
		Domains:     []string{domain},
		IsWildcard:  false,
		NotAfter:    time.Now().Add(90 * 24 * time.Hour), // Approximate
		Services:    make(map[string]bool),
		Certificate: cert,
	}

	r.mu.Lock()
	r.certificates[managed.Identifier] = managed
	r.domainToCert[domain] = managed.Identifier
	r.mu.Unlock()

	return cert, nil
}

// getCertificateForDomain retrieves a certificate for a domain
func (r *CertificateRegistry) getCertificateForDomain(domain string) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	certID, ok := r.domainToCert[domain]
	if !ok {
		return nil, ErrCertificateNotFound
	}

	cert := r.certificates[certID]
	if cert == nil || cert.Certificate == nil {
		return nil, ErrCertificateNotFound
	}

	return cert.Certificate, nil
}

// HTTPHandler returns an HTTP handler for ACME HTTP-01 challenges
func (r *CertificateRegistry) HTTPHandler(handler http.Handler) http.Handler {
	if r.httpFallback != nil {
		return r.httpFallback.HTTPHandler(handler)
	}
	return handler
}

// State persistence

type registryState struct {
	Certificates map[string]*ManagedCertificate `json:"certificates"`
	DomainMap    map[string]string              `json:"domain_map"`
	SavedAt      time.Time                      `json:"saved_at"`
}

func (r *CertificateRegistry) loadState() error {
	if r.config.StatePath == "" {
		return nil
	}

	data, err := os.ReadFile(r.config.StatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state registryState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	// Restore certificates (without the actual TLS certificates - those will be reprovisioned)
	for id, cert := range state.Certificates {
		r.certificates[id] = cert
		cert.Services = make(map[string]bool) // Reset services, will be re-registered
	}
	r.domainToCert = state.DomainMap

	slog.Info("Loaded certificate registry state",
		"certificates", len(r.certificates),
		"domains", len(r.domainToCert),
		"savedAt", state.SavedAt,
	)

	return nil
}

func (r *CertificateRegistry) saveState() error {
	if r.config.StatePath == "" {
		return nil
	}

	r.mu.RLock()
	state := registryState{
		Certificates: r.certificates,
		DomainMap:    r.domainToCert,
		SavedAt:      time.Now(),
	}
	r.mu.RUnlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically
	tmpPath := r.config.StatePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, r.config.StatePath)
}

// GetStats returns statistics about the registry
func (r *CertificateRegistry) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	wildcardCount := 0
	httpCount := 0
	expiringCount := 0
	now := time.Now()

	for _, cert := range r.certificates {
		if cert.IsWildcard {
			wildcardCount++
		}
		if cert.Identifier[:6] == "http01" {
			httpCount++
		}
		if time.Until(cert.NotAfter) < 30*24*time.Hour {
			expiringCount++
		}
	}

	return map[string]interface{}{
		"ready":               r.ready,
		"total_certificates":  len(r.certificates),
		"wildcard_certs":      wildcardCount,
		"http01_certs":        httpCount,
		"expiring_soon":       expiringCount,
		"domains_mapped":      len(r.domainToCert),
		"dns_provider":        r.config.DNSProvider,
		"provisioning_active": len(r.provisioning),
		"timestamp":           now,
	}
}
