package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/basecamp/kamal-proxy/internal/server/acme/providers"
)

const (
	// LetsEncryptProduction is the production ACME directory
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	// LetsEncryptStaging is the staging ACME directory for testing
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// MaxSANsPerCertificate is the maximum number of SANs allowed per certificate
	// Let's Encrypt limit is 100
	MaxSANsPerCertificate = 100
)

var (
	ErrNoDomains          = errors.New("no domains to provision")
	ErrCertNotFound       = errors.New("certificate not found")
	ErrManagerNotReady    = errors.New("certificate manager not initialized")
	ErrProvisioningFailed = errors.New("certificate provisioning failed")
)

// SANCertManagerConfig holds configuration for the SAN certificate manager
type SANCertManagerConfig struct {
	// Email is the ACME account email (required)
	Email string

	// Directory is the ACME directory URL (defaults to Let's Encrypt production)
	Directory string

	// CachePath is where certificates are stored
	CachePath string

	// StatePath is where manager state is persisted
	StatePath string

	// DNSProvider names the DNS-01 challenge provider. Empty (or "none") leaves
	// issuance on HTTP-01, which cannot answer for a wildcard.
	DNSProvider acme.ProviderName

	// PreferWildcard collapses a batch of sibling subdomains into a single
	// wildcard certificate when a DNS provider can validate one.
	PreferWildcard bool

	// HTTPFallback retries an order over HTTP-01 when the DNS-01 attempt fails.
	// It has no effect on wildcards, which only DNS-01 can validate.
	HTTPFallback bool
}

// SANCertManager manages SAN certificates with domain batching.
// It batches up to 100 domains into a single certificate,
// reducing the number of certificates and avoiding rate limits.
type SANCertManager struct {
	mu      sync.RWMutex
	stateMu sync.Mutex // serializes state-file snapshots and writes
	config  SANCertManagerConfig

	// ACME clients. Both are built on the SAME account (`acme_user.json`), so
	// the whole proxy has exactly one ACME identity no matter which challenge
	// type answers an order.
	client    *lego.Client // HTTP-01
	dnsClient *lego.Client // DNS-01, only when a provider is configured
	user      *acmeUser

	// Issuance seams, so the strategy can be exercised without a live
	// directory. Initialize points them at the clients above.
	httpObtainer certObtainer
	dnsObtainer  certObtainer

	// grouper decides when a batch is better served by a wildcard.
	grouper *DomainGrouper

	// bucket is the ceiling on ACME orders. Every issuance path in the process
	// -- handshake-driven, dynamic issuer, renewer -- draws from this one
	// bucket, so they cannot add up to more orders than the limit allows.
	bucket *tokenBucket

	// Certificate storage: certID -> certificate
	certificates map[string]*ManagedCert

	// Domain to certificate mapping
	domainToCert map[string]string

	// Pending domains waiting to be batched: domain -> service name
	pendingDomains map[string]string

	// Deploy-registered hosts allowed to provision synchronously
	registeredDomains map[string]struct{}

	// Runtime-learned domains from tls-domains-source: domain -> service name
	dynamicDomains map[string]string

	// Callback to request asynchronous issuance for a dynamic domain
	dynamicCertRequester func(domain, service string)

	// Currently provisioning: rootDomain -> done channel
	provisioning map[string]chan struct{}

	// HTTP-01 challenge tokens: token -> the challenge it answers
	challengeTokens map[string]http01Challenge

	// State
	ready bool
}

// ManagedCert represents a certificate managed by the manager
type ManagedCert struct {
	Identifier  string           `json:"identifier"`
	Domains     []string         `json:"domains"`
	NotAfter    time.Time        `json:"not_after"`
	Certificate *tls.Certificate `json:"-"` // Not persisted, loaded from files
}

// http01Challenge is one presented challenge: the key authorization to serve,
// and the single domain whose validation request may receive it.
type http01Challenge struct {
	domain  string
	keyAuth string
}

// acmeUser implements registration.User for lego
type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          *ecdsa.PrivateKey      `json:"-"`
	KeyPEM       []byte                 `json:"key_pem"`
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.Key }

// NewSANCertManager creates a new SAN certificate manager
func NewSANCertManager(config SANCertManagerConfig) (*SANCertManager, error) {
	if config.Email == "" {
		return nil, errors.New("email is required for ACME registration")
	}

	if config.Directory == "" {
		config.Directory = LetsEncryptProduction
	}

	grouper := NewDomainGrouper()
	grouper.PreferWildcard = config.PreferWildcard

	manager := &SANCertManager{
		config:            config,
		grouper:           grouper,
		bucket:            newTokenBucket(DefaultIssuanceBurst, DefaultIssuanceRefillInterval),
		certificates:      make(map[string]*ManagedCert),
		domainToCert:      make(map[string]string),
		pendingDomains:    make(map[string]string),
		registeredDomains: make(map[string]struct{}),
		dynamicDomains:    make(map[string]string),
		provisioning:      make(map[string]chan struct{}),
		challengeTokens:   make(map[string]http01Challenge),
	}

	// Ensure cache directory exists
	if config.CachePath != "" {
		if err := os.MkdirAll(config.CachePath, 0700); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	return manager, nil
}

// Initialize sets up the ACME client and loads persisted state
func (m *SANCertManager) Initialize(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Load or create ACME user
	user, err := m.loadOrCreateUser()
	if err != nil {
		return fmt.Errorf("failed to setup ACME user: %w", err)
	}
	m.user = user

	// Create lego config
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = m.config.Directory
	legoConfig.Certificate.KeyType = certcrypto.EC256

	// Create ACME client
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Setup HTTP-01 challenge provider using our custom provider
	httpProvider := &memoryHTTP01Provider{manager: m}
	if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
		return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

	m.client = client
	m.httpObtainer = client.Certificate

	// Register with ACME if not already registered
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("failed to register with ACME: %w", err)
		}
		user.Registration = reg

		// Save user with registration
		if err := m.saveUser(); err != nil {
			slog.Warn("Failed to save ACME user", "error", err)
		}
	}

	// The DNS-01 client rides the same registered account, so a proxy with a
	// provider configured still has exactly one ACME identity.
	if err := m.initDNSClient(); err != nil {
		return err
	}

	// Load persisted state
	if err := m.loadState(); err != nil {
		slog.Warn("Failed to load certificate state", "error", err)
	}

	// Adopt anything the deleted certificate registry left behind, so an
	// upgrade does not re-order certificates the proxy already holds.
	m.importLegacyHTTP01Cache()

	m.ready = true
	slog.Info("SAN certificate manager initialized",
		"email", m.config.Email,
		"directory", m.config.Directory,
		"dns_provider", m.config.DNSProvider,
		"prefer_wildcard", m.config.PreferWildcard,
		"http_fallback", m.config.HTTPFallback,
	)

	return nil
}

// initDNSClient builds the DNS-01 client when a provider is configured. A
// provider that cannot be constructed is fatal unless HTTP-01 is allowed to
// stand in for it. Must be called with m.mu held.
func (m *SANCertManager) initDNSClient() error {
	if m.config.DNSProvider == "" || m.config.DNSProvider == "none" {
		return nil
	}

	dnsProvider, err := providers.NewProvider(m.config.DNSProvider)
	if err != nil {
		if !m.config.HTTPFallback {
			return fmt.Errorf("failed to create DNS provider %q: %w", m.config.DNSProvider, err)
		}
		slog.Warn("DNS provider not available, staying on HTTP-01",
			"provider", m.config.DNSProvider, "error", err)
		return nil
	}

	legoConfig := lego.NewConfig(m.user)
	legoConfig.CADirURL = m.config.Directory
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("failed to create DNS-01 ACME client: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
		return fmt.Errorf("failed to set DNS-01 provider: %w", err)
	}

	m.dnsClient = client
	m.dnsObtainer = client.Certificate
	m.grouper.DNSProviderAvailable = true

	slog.Info("DNS-01 challenge solver initialized", "provider", m.config.DNSProvider)
	return nil
}

// memoryHTTP01Provider is a custom HTTP-01 challenge provider that stores tokens in memory
type memoryHTTP01Provider struct {
	manager *SANCertManager
}

func (p *memoryHTTP01Provider) Present(domain, token, keyAuth string) error {
	p.manager.mu.Lock()
	p.manager.challengeTokens[token] = http01Challenge{domain: domain, keyAuth: keyAuth}
	p.manager.mu.Unlock()
	slog.Debug("HTTP-01 challenge presented", "domain", domain, "token", token)
	return nil
}

func (p *memoryHTTP01Provider) CleanUp(domain, token, keyAuth string) error {
	p.manager.mu.Lock()
	delete(p.manager.challengeTokens, token)
	p.manager.mu.Unlock()
	slog.Debug("HTTP-01 challenge cleaned up", "domain", domain, "token", token)
	return nil
}

// RegisterDomain registers a domain for certificate management
func (m *SANCertManager) RegisterDomain(domain string, service string) error {
	// A catch-all service's normalized host is "": not a provisionable domain
	if domain == "" {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.ready {
		return ErrManagerNotReady
	}

	m.registeredDomains[domain] = struct{}{}

	// Check if domain already has a certificate, its own or a wildcard's
	if certID := m.certIDCovering(domain); certID != "" {
		cert := m.certificates[certID]
		if cert != nil && time.Until(cert.NotAfter) > 24*time.Hour {
			slog.Debug("Domain already has valid certificate",
				"domain", domain,
				"certificate", certID,
			)
			return nil
		}
	}

	// Check if domain is covered by an existing valid SAN certificate
	for _, cert := range m.certificates {
		if time.Until(cert.NotAfter) <= 24*time.Hour {
			continue
		}
		for _, d := range cert.Domains {
			if d == domain {
				m.domainToCert[domain] = cert.Identifier
				slog.Debug("Domain covered by existing SAN certificate",
					"domain", domain,
					"certificate", cert.Identifier,
				)
				return nil
			}
		}
	}

	// Add to pending domains for batched provisioning
	m.pendingDomains[domain] = service
	slog.Debug("Domain added to pending batch",
		"domain", domain,
		"service", service,
		"pending_count", len(m.pendingDomains),
	)

	return nil
}

// UnregisterDomain removes a domain from management
func (m *SANCertManager) UnregisterDomain(domain string, service string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pendingDomains, domain)
	delete(m.registeredDomains, domain)
	return nil
}

// GetCertificate returns a certificate for the TLS handshake.
//
// Provisioning is gated by a hard allowlist: deploy-registered hosts provision
// synchronously (the original behavior), dynamic domains are queued for
// asynchronous issuance, and any other server name is refused outright so a
// catch-all service cannot be used to burn rate limits on scanner-supplied
// names.
func (m *SANCertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		return nil, errors.New("no server name provided")
	}

	m.mu.RLock()
	ready := m.ready
	var cert *ManagedCert
	if certID := m.certIDCovering(domain); certID != "" {
		cert = m.certificates[certID]
	}
	_, isRegistered := m.registeredDomains[domain]
	dynamicService, isDynamic := m.dynamicDomains[domain]
	m.mu.RUnlock()

	if !ready {
		return nil, ErrManagerNotReady
	}

	if cert != nil && cert.Certificate != nil {
		// Return existing valid certificate
		if time.Until(cert.NotAfter) > 24*time.Hour {
			return cert.Certificate, nil
		}

		if isRegistered {
			slog.Info("Certificate expiring soon, will reprovision",
				"domain", domain,
				"expiresAt", cert.NotAfter,
			)
		} else if time.Until(cert.NotAfter) > 0 {
			// Dynamic and evicted domains keep serving a still-valid
			// certificate; the renewal loop is responsible for rotating it.
			if isDynamic {
				m.requestDynamicCertificate(domain, dynamicService)
			}
			return cert.Certificate, nil
		}
	}

	if isRegistered {
		// Need to provision certificate
		return m.provisionCertificate(hello.Context(), domain)
	}

	if isDynamic {
		m.requestDynamicCertificate(domain, dynamicService)
		return nil, ErrCertNotFound
	}

	slog.Debug("Refusing to provision certificate for unknown server name", "domain", domain)
	return nil, ErrCertNotFound
}

// provisionCertificate provisions a certificate for a domain.
//
// It batches together ALL pending domains (up to MaxSANsPerCertificate) into a
// single certificate, which minimizes the number of certificates and stays well
// inside Let's Encrypt's limits. With a DNS provider configured and
// --acme-prefer-wildcard set, sibling subdomains collapse further into one
// wildcard.
//
// The caller reached here only for a deploy-registered host, so the allowlist
// has already been consulted. The rate limit has not, and this path is
// handshake-driven, so it takes a token before ordering.
func (m *SANCertManager) provisionCertificate(ctx context.Context, domain string) (*tls.Certificate, error) {
	// Use a single provisioning lock - we batch everything together
	const provisioningKey = "_batch_"

	m.mu.Lock()
	if done, ok := m.provisioning[provisioningKey]; ok {
		m.mu.Unlock()
		// Wait for existing provisioning to complete
		select {
		case <-done:
			return m.getCertForDomain(domain)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Collect ALL pending domains (up to MaxSANsPerCertificate)
	domainsToProvision := []string{domain}
	for pendingDomain := range m.pendingDomains {
		if pendingDomain != domain {
			domainsToProvision = append(domainsToProvision, pendingDomain)
		}
		if len(domainsToProvision) >= MaxSANsPerCertificate {
			break
		}
	}

	// Start provisioning
	done := make(chan struct{})
	m.provisioning[provisioningKey] = done

	// Remove domains from pending
	for _, d := range domainsToProvision {
		delete(m.pendingDomains, d)
	}
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.provisioning, provisioningKey)
		close(done)
		m.mu.Unlock()
	}()

	// Sort the planned identifier set for consistent certificate identifiers
	sortedDomains := m.planIssuanceDomains(domainsToProvision)
	slices.Sort(sortedDomains)

	slog.Info("Provisioning SAN certificate",
		"requested", domainsToProvision,
		"domains", sortedDomains,
		"batch_size", len(sortedDomains),
	)

	if err := m.bucket.Take(ctx); err != nil {
		m.restorePending(domainsToProvision)
		return nil, err
	}

	// Request certificate for all domains
	request := certificate.ObtainRequest{
		Domains: sortedDomains,
		Bundle:  true,
	}

	resource, err := m.obtainCertificate(request)
	if err != nil {
		// Re-add domains to pending so they can be retried
		m.restorePending(domainsToProvision)
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	managed, err := m.adoptCertificate(resource, sortedDomains)
	if err != nil {
		return nil, err
	}

	return managed.Certificate, nil
}

// adoptCertificate parses an issued certificate, installs it in the manager's
// maps, and persists it. sortedDomains must be the sorted identifier set the
// certificate was ordered for.
func (m *SANCertManager) adoptCertificate(resource *certificate.Resource, sortedDomains []string) (*ManagedCert, error) {
	// Parse the certificate
	tlsCert, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse the leaf certificate to get the actual expiry
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	tlsCert.Leaf = leaf
	notAfter := leaf.NotAfter

	// Generate collision-resistant certificate ID from full domain list
	certID := sanCertID(sortedDomains)
	managed := &ManagedCert{
		Identifier:  certID,
		Domains:     sortedDomains,
		NotAfter:    notAfter,
		Certificate: &tlsCert,
	}

	m.mu.Lock()
	m.certificates[certID] = managed
	for _, d := range sortedDomains {
		m.domainToCert[d] = certID
	}
	m.mu.Unlock()

	// Save certificate to disk
	if err := m.saveCertificate(certID, resource); err != nil {
		slog.Warn("Failed to save certificate", "error", err)
	}

	// Persist state (called without lock held)
	if err := m.persistState(); err != nil {
		slog.Warn("Failed to save state", "error", err)
	}

	slog.Info("Certificate provisioned successfully",
		"identifier", certID,
		"domains", sortedDomains,
		"batch_size", len(sortedDomains),
		"expires", notAfter,
	)

	return managed, nil
}

// getCertForDomain retrieves a certificate for a domain
func (m *SANCertManager) getCertForDomain(domain string) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	certID := m.certIDCovering(domain)
	if certID == "" {
		return nil, ErrCertNotFound
	}

	cert := m.certificates[certID]
	if cert == nil || cert.Certificate == nil {
		return nil, ErrCertNotFound
	}

	return cert.Certificate, nil
}

// HTTPHandler returns the HTTP handler for ACME challenges.
//
// A key authorization is served only to a validation request for the domain the
// challenge was presented for. A token exists only while an order we chose to
// place is in flight, so this is belt and braces -- but it is the one handler
// the proxy exposes unauthenticated on port 80, and RFC 8555 requires the
// validating server to send the identifier as the Host header, so the check
// costs nothing real.
func (m *SANCertManager) HTTPHandler(fallback http.Handler) http.Handler {
	const challengePrefix = "/.well-known/acme-challenge/"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is an ACME challenge request
		if token, ok := strings.CutPrefix(r.URL.Path, challengePrefix); ok && token != "" {
			m.mu.RLock()
			challenge, known := m.challengeTokens[token]
			m.mu.RUnlock()

			switch {
			case !known:
				slog.Debug("HTTP-01 challenge token not found", "token", token)
			case !strings.EqualFold(requestHostname(r), challenge.domain):
				slog.Warn("Refusing HTTP-01 challenge for a mismatched host",
					"token", token, "challenge_domain", challenge.domain, "request_host", r.Host)
			default:
				slog.Debug("Serving HTTP-01 challenge", "domain", challenge.domain, "token", token)
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(challenge.keyAuth))
				return
			}
		}

		fallback.ServeHTTP(w, r)
	})
}

// requestHostname is the Host header without its port or trailing dot.
func requestHostname(r *http.Request) string {
	host := r.Host
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	return strings.TrimSuffix(host, ".")
}

// GetStats returns statistics about the manager
func (m *SANCertManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	expiringCount := 0
	for _, cert := range m.certificates {
		if time.Until(cert.NotAfter) < 30*24*time.Hour {
			expiringCount++
		}
	}

	return map[string]interface{}{
		"ready":               m.ready,
		"total_certificates":  len(m.certificates),
		"domains_mapped":      len(m.domainToCert),
		"pending_domains":     len(m.pendingDomains),
		"registered_domains":  len(m.registeredDomains),
		"dynamic_domains":     len(m.dynamicDomains),
		"expiring_soon":       expiringCount,
		"provisioning_active": len(m.provisioning),
	}
}

// Persistence methods

func (m *SANCertManager) loadOrCreateUser() (*acmeUser, error) {
	userPath := filepath.Join(m.config.CachePath, "acme_user.json")

	data, err := os.ReadFile(userPath)
	if err == nil {
		var user acmeUser
		if err := json.Unmarshal(data, &user); err == nil {
			// Decode the private key
			key, err := certcrypto.ParsePEMPrivateKey(user.KeyPEM)
			if err == nil {
				if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
					user.Key = ecKey
					return &user, nil
				}
			}
		}
	}

	// Create new user
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	user := &acmeUser{
		Email: m.config.Email,
		Key:   privateKey,
	}

	return user, nil
}

func (m *SANCertManager) saveUser() error {
	if m.config.CachePath == "" {
		return nil
	}

	keyPEM := certcrypto.PEMEncode(m.user.Key)
	m.user.KeyPEM = keyPEM

	data, err := json.MarshalIndent(m.user, "", "  ")
	if err != nil {
		return err
	}

	userPath := filepath.Join(m.config.CachePath, "acme_user.json")
	return os.WriteFile(userPath, data, 0600)
}

func (m *SANCertManager) saveCertificate(certID string, resource *certificate.Resource) error {
	if m.config.CachePath == "" {
		return nil
	}

	certDir := filepath.Join(m.config.CachePath, sanitizeFilename(certID))
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}

	// Save certificate
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), resource.Certificate, 0600); err != nil {
		return err
	}

	// Save private key
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), resource.PrivateKey, 0600); err != nil {
		return err
	}

	return nil
}

type managerState struct {
	Certificates map[string]*ManagedCert `json:"certificates"`
	DomainMap    map[string]string       `json:"domain_map"`
	SavedAt      time.Time               `json:"saved_at"`
}

func (m *SANCertManager) loadState() error {
	if m.config.StatePath == "" {
		return nil
	}

	data, err := os.ReadFile(m.config.StatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state managerState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	// Load certificates from disk
	for id, cert := range state.Certificates {
		if m.config.CachePath != "" {
			certDir := filepath.Join(m.config.CachePath, sanitizeFilename(id))
			certPath := filepath.Join(certDir, "cert.pem")
			keyPath := filepath.Join(certDir, "key.pem")

			tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				cert.Certificate = &tlsCert
			}
		}
		m.certificates[id] = cert
	}

	m.domainToCert = state.DomainMap

	slog.Info("Loaded certificate manager state",
		"certificates", len(m.certificates),
		"domains", len(m.domainToCert),
	)

	return nil
}

func (m *SANCertManager) persistState() error {
	if m.config.StatePath == "" {
		return nil
	}

	// Serialize snapshot+write: issuer goroutines, the renewer, and
	// handshake-driven provisioning all persist concurrently, and interleaved
	// writes to the shared .tmp file would corrupt it.
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	m.mu.RLock()
	certs := make(map[string]*ManagedCert, len(m.certificates))
	for k, v := range m.certificates {
		certs[k] = v
	}
	domainMap := make(map[string]string, len(m.domainToCert))
	for k, v := range m.domainToCert {
		domainMap[k] = v
	}
	m.mu.RUnlock()

	return m.writeState(managerState{
		Certificates: certs,
		DomainMap:    domainMap,
		SavedAt:      time.Now(),
	})
}

func (m *SANCertManager) writeState(state managerState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := m.config.StatePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, m.config.StatePath)
}

func sanCertID(domains []string) string {
	h := sha256.New()
	for _, d := range domains {
		h.Write([]byte(d))
		h.Write([]byte{0})
	}
	return "san:" + hex.EncodeToString(h.Sum(nil))[:16]
}

func sanitizeFilename(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
