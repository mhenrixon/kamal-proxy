package server

import (
	"crypto/tls"
	"net/http"
)

// RegistryCertManager implements CertManager backed by a CertificateRegistry
type RegistryCertManager struct {
	registry *CertificateRegistry
	domains  []string
	service  string
}

// NewRegistryCertManager creates a new RegistryCertManager
func NewRegistryCertManager(registry *CertificateRegistry, domains []string, service string) *RegistryCertManager {
	return &RegistryCertManager{
		registry: registry,
		domains:  domains,
		service:  service,
	}
}

// GetCertificate returns the certificate for the given TLS client hello
func (m *RegistryCertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.registry.GetCertificate(hello)
}

// HTTPHandler wraps the given handler with ACME HTTP-01 challenge handling
func (m *RegistryCertManager) HTTPHandler(handler http.Handler) http.Handler {
	return m.registry.HTTPHandler(handler)
}

// RegisterDomains registers the domains with the registry
func (m *RegistryCertManager) RegisterDomains() error {
	for _, domain := range m.domains {
		if err := m.registry.RegisterDomain(domain, m.service); err != nil {
			return err
		}
	}
	return nil
}

// UnregisterDomains unregisters the domains from the registry
func (m *RegistryCertManager) UnregisterDomains() error {
	for _, domain := range m.domains {
		if err := m.registry.UnregisterDomain(domain, m.service); err != nil {
			return err
		}
	}
	return nil
}
