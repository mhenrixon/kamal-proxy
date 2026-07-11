package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

// Dynamic domain support for the SAN certificate manager.
//
// Domains learned at runtime (from a service's tls-domains-source) form a hard
// allowlist alongside deploy-registered hosts: GetCertificate only provisions
// certificates for domains in that union. Dynamic domains are issued
// asynchronously by the domain issuer, never on the handshake path.

// SetDynamicCertRequester installs the callback used to request asynchronous
// issuance for a dynamic domain that has no usable certificate yet.
func (m *SANCertManager) SetDynamicCertRequester(fn func(domain, service string)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dynamicCertRequester = fn
}

// SetDynamicDomains replaces the dynamic domain set for a service.
func (m *SANCertManager) SetDynamicDomains(service string, domains []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for domain, owner := range m.dynamicDomains {
		if owner == service {
			delete(m.dynamicDomains, domain)
		}
	}

	for _, domain := range domains {
		m.dynamicDomains[domain] = service
	}
}

// DynamicDomains returns the dynamic domains currently owned by a service.
func (m *SANCertManager) DynamicDomains(service string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domains := []string{}
	for domain, owner := range m.dynamicDomains {
		if owner == service {
			domains = append(domains, domain)
		}
	}
	return domains
}

// DomainAllowed reports whether a domain may have a certificate provisioned:
// it must be deploy-registered or present in a service's dynamic set.
func (m *SANCertManager) DomainAllowed(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.registeredDomains[domain]; ok {
		return true
	}
	_, ok := m.dynamicDomains[domain]
	return ok
}

// HasCertificate reports whether the manager has ever issued a certificate
// covering the domain, even an expired one.
func (m *SANCertManager) HasCertificate(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.domainToCert[domain]
	return ok
}

// HasValidCertificate reports whether the domain is covered by a loaded
// certificate that is not due for replacement.
func (m *SANCertManager) HasValidCertificate(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	certID, ok := m.domainToCert[domain]
	if !ok {
		return false
	}

	cert := m.certificates[certID]
	return cert != nil && cert.Certificate != nil && time.Until(cert.NotAfter) > 24*time.Hour
}

// requestDynamicCertificate asks the issuer (when wired) to provision a
// certificate for a dynamic domain, without blocking the handshake.
func (m *SANCertManager) requestDynamicCertificate(domain, service string) {
	m.mu.RLock()
	requester := m.dynamicCertRequester
	m.mu.RUnlock()

	if requester != nil {
		requester(domain, service)
	}
}

// dynamicOwner returns the service owning a dynamic domain.
func (m *SANCertManager) dynamicOwner(domain string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	service, ok := m.dynamicDomains[domain]
	return service, ok
}

// ManagedCertificates returns a snapshot of the managed certificates.
func (m *SANCertManager) ManagedCertificates() []*ManagedCert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	certs := make([]*ManagedCert, 0, len(m.certificates))
	for _, cert := range m.certificates {
		certs = append(certs, cert)
	}
	return certs
}

// removeCertificate drops a certificate from the maps, deletes its cached
// files, and persists. Domains still mapped to it are unmapped.
func (m *SANCertManager) removeCertificate(certID string) {
	m.mu.Lock()
	delete(m.certificates, certID)
	for domain, id := range m.domainToCert {
		if id == certID {
			delete(m.domainToCert, domain)
		}
	}
	m.mu.Unlock()

	if m.config.CachePath != "" {
		if err := os.RemoveAll(filepath.Join(m.config.CachePath, sanitizeFilename(certID))); err != nil {
			slog.Warn("Failed to remove certificate files", "certificate", certID, "error", err)
		}
	}

	if err := m.persistState(); err != nil {
		slog.Warn("Failed to save state", "error", err)
	}
}

// acmeCertifier returns the ACME client's certifier, or nil before Initialize.
func (m *SANCertManager) acmeCertifier() *certificate.Certifier {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.client == nil {
		return nil
	}
	return m.client.Certificate
}
