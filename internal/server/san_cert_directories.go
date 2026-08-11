package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

// Per-service ACME directory selection.
//
// A service deployed with --tls-staging carries its own ACME directory in
// ServiceOptions; the shared SAN manager honors it by keeping one ACME
// identity per directory. The run-level directory keeps the original account
// and clients; any other directory gets its own account and client bundle,
// registered lazily on the first order that needs it. Issuance resolves the
// directory from the domains' owning service, and batches never mix
// directories — the dynamic issuer batches per service, the handshake path
// partitions by directory — so one order always has exactly one identity.

// directoryClients is the ACME identity for one non-default directory.
type directoryClients struct {
	user         *acmeUser
	httpObtainer certObtainer
	dnsObtainer  certObtainer
	dnsObtainers map[acme.ProviderName]certObtainer
}

// SetServiceDirectory records a service's ACME directory override. An empty
// directory, or the run-level one, clears the override.
func (m *SANCertManager) SetServiceDirectory(service, directory string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if directory == "" || directory == m.config.Directory {
		delete(m.serviceDirectories, service)
		return
	}
	m.serviceDirectories[service] = directory
}

// directoryForService returns the ACME directory a service's certificates are
// issued against.
func (m *SANCertManager) directoryForService(service string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.directoryForServiceLocked(service)
}

func (m *SANCertManager) directoryForServiceLocked(service string) string {
	if directory, ok := m.serviceDirectories[service]; ok {
		return directory
	}
	return m.config.Directory
}

// ownerOf returns the service that owns a domain, whether registered at
// deploy time, learned from a domain source, or waiting in the pending batch.
func (m *SANCertManager) ownerOf(domain string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ownerOfLocked(domain)
}

// ownerOfLocked resolves a domain's owning service; a wildcard resolves
// through a concrete domain it covers, mirroring coversAllowedDomain. A
// pending entry with an empty service (a batch survivor restored by
// restorePending) does not name an owner. Callers must hold m.mu.
func (m *SANCertManager) ownerOfLocked(domain string) (string, bool) {
	if strings.HasPrefix(domain, "*.") {
		for covered, service := range m.registeredDomains {
			if matchesWildcard(domain, covered) && service != "" {
				return service, true
			}
		}
		for covered, service := range m.dynamicDomains {
			if matchesWildcard(domain, covered) && service != "" {
				return service, true
			}
		}
		return "", false
	}

	if service, ok := m.registeredDomains[domain]; ok && service != "" {
		return service, true
	}
	if service, ok := m.dynamicDomains[domain]; ok && service != "" {
		return service, true
	}
	if service, ok := m.pendingDomains[domain]; ok && service != "" {
		return service, true
	}
	return "", false
}

// directoryForDomains resolves the directory an order for these domains must
// use: the first resolvable owner's directory. Batches are single-service by
// construction, so the first owner speaks for the whole order; with no owner
// at all, the run-level directory answers.
func (m *SANCertManager) directoryForDomains(domains []string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, domain := range domains {
		if service, ok := m.ownerOfLocked(domain); ok {
			return m.directoryForServiceLocked(service)
		}
	}
	return m.config.Directory
}

// directoryForDomainLocked is directoryForDomains for one domain with m.mu
// already held, for the handshake batching path.
func (m *SANCertManager) directoryForDomainLocked(domain string) string {
	if service, ok := m.ownerOfLocked(domain); ok {
		return m.directoryForServiceLocked(service)
	}
	return m.config.Directory
}

// desiredDirectoryForCert reports the directory the owning service of a
// certificate's domains currently wants. known is false when no owner is
// resolvable — the certificate must then keep its recorded directory rather
// than churn against the default, because services may simply not have
// re-attached yet after a restart.
func (m *SANCertManager) desiredDirectoryForCert(cert *ManagedCert) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, domain := range cert.Domains {
		if service, ok := m.ownerOfLocked(domain); ok {
			return m.directoryForServiceLocked(service), true
		}
	}
	return "", false
}

// normalizeDirectory resolves an empty (legacy) recorded directory to the
// run-level one for comparison.
func (m *SANCertManager) normalizeDirectory(directory string) string {
	if directory == "" {
		return m.config.Directory
	}
	return directory
}

// accountFileForDirectory names the account key file for a directory. The
// run-level directory keeps the original acme_user.json — existing accounts
// keep working across upgrades — the well-known Let's Encrypt staging URL
// gets a readable name, and anything else is keyed by a URL hash.
func (m *SANCertManager) accountFileForDirectory(directory string) string {
	switch directory {
	case m.config.Directory:
		return acmeUserFile
	case LetsEncryptStaging:
		return "acme_user_staging.json"
	}

	sum := sha256.Sum256([]byte(directory))
	return "acme_user_" + hex.EncodeToString(sum[:4]) + ".json"
}

// clientsForDirectory returns the client bundle for a directory other than
// the run-level one, building and registering its account on first use.
func (m *SANCertManager) clientsForDirectory(directory string) (*directoryClients, error) {
	m.mu.RLock()
	bundle := m.directoryClients[directory]
	m.mu.RUnlock()

	if bundle != nil {
		return bundle, nil
	}

	// Single-flight the build: account registration is a network call, and
	// two concurrent orders must not register two accounts for one directory.
	m.directoryInitMu.Lock()
	defer m.directoryInitMu.Unlock()

	m.mu.RLock()
	bundle = m.directoryClients[directory]
	m.mu.RUnlock()
	if bundle != nil {
		return bundle, nil
	}

	bundle, err := m.buildDirectoryClients(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to set up ACME clients for %s: %w", directory, err)
	}

	m.mu.Lock()
	m.directoryClients[directory] = bundle
	m.mu.Unlock()

	return bundle, nil
}

// buildDirectoryClients constructs the ACME identity for one directory: its
// own account (loaded or created, registered if new) and obtainers mirroring
// the primary clients — HTTP-01 plus whatever DNS-01 solvers the run-level
// configuration names, so a zone mapping answers a staging order the same way
// it answers a production one.
func (m *SANCertManager) buildDirectoryClients(directory string) (*directoryClients, error) {
	accountFile := m.accountFileForDirectory(directory)

	user, err := m.loadOrCreateUser(accountFile)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ACME user: %w", err)
	}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = directory
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// The challenge token map is shared: tokens are per-order, so one handler
	// serves every identity.
	if err := client.Challenge.SetHTTP01Provider(&memoryHTTP01Provider{manager: m}); err != nil {
		return nil, fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to register with ACME: %w", err)
		}
		user.Registration = reg

		if err := m.saveUser(user, accountFile); err != nil {
			slog.Warn("Failed to save ACME user", "directory", directory, "error", err)
		}
	}

	dnsObtainer, dnsObtainers, err := m.buildDNSObtainers(user, directory)
	if err != nil {
		return nil, err
	}

	slog.Info("ACME clients initialized for directory",
		"directory", directory, "account_file", accountFile)

	return &directoryClients{
		user:         user,
		httpObtainer: client.Certificate,
		dnsObtainer:  dnsObtainer,
		dnsObtainers: dnsObtainers,
	}, nil
}

// obtainersFor resolves the clients answering one order: the owning service's
// directory picks the ACME identity, and zone selection picks the DNS-01
// solver within it. A nil DNS obtainer means HTTP-01 territory.
func (m *SANCertManager) obtainersFor(domains []string) (httpObtainer, dnsObtainer certObtainer, err error) {
	directory := m.directoryForDomains(domains)

	if directory == m.config.Directory {
		dnsObtainer, err := m.orderObtainer(domains)
		if err != nil {
			return nil, nil, err
		}

		m.mu.RLock()
		httpObtainer := m.httpObtainer
		m.mu.RUnlock()

		return httpObtainer, dnsObtainer, nil
	}

	bundle, err := m.clientsForDirectory(directory)
	if err != nil {
		return nil, nil, err
	}

	dnsObtainer, err = orderObtainerFrom(m.selection, domains, bundle.dnsObtainer, bundle.dnsObtainers)
	if err != nil {
		return nil, nil, err
	}

	return bundle.httpObtainer, dnsObtainer, nil
}

// renewalInfoObtainer returns the identity that should answer an ARI query
// for a certificate covering these domains: the one that issued it. A bundle
// that has not been built this run returns nil rather than registering an
// account for a read-only query; callers fall back to the renewal window
// heuristic.
func (m *SANCertManager) renewalInfoObtainer(domains []string) renewalInfoGetter {
	directory := m.config.Directory
	if len(domains) > 0 {
		if certID := m.certIDForDomain(domains[0]); certID != "" {
			m.mu.RLock()
			if cert := m.certificates[certID]; cert != nil {
				directory = m.normalizeDirectory(cert.Directory)
			}
			m.mu.RUnlock()
		}
	}

	if directory == m.config.Directory {
		certifier := m.acmeCertifier()
		if certifier == nil {
			return nil
		}
		return certifier
	}

	m.mu.RLock()
	bundle := m.directoryClients[directory]
	m.mu.RUnlock()
	if bundle == nil {
		return nil
	}

	getter, ok := bundle.httpObtainer.(renewalInfoGetter)
	if !ok {
		return nil
	}
	return getter
}
