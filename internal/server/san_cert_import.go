package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

// legacyHTTP01CacheDir is where the deleted certificate registry kept its
// autocert HTTP-01 fallback cache, under the shared certificate path.
const legacyHTTP01CacheDir = "http01"

// importLegacyHTTP01Cache adopts certificates the deleted certificate registry
// left in its autocert cache.
//
// The registry never wrote its DNS-01 certificates to disk at all, so an
// upgrade from v1.0.0.0 has live key material in exactly one place: the
// autocert DirCache. Without this, the first boot after the upgrade would
// re-order every certificate the proxy already holds -- the fastest way there
// is to spend an account's Let's Encrypt rate limit on nothing.
//
// Adoption does NOT put a domain on the allowlist. An imported certificate
// serves if something still routes its name, and the renewer garbage-collects
// it otherwise.
func (m *SANCertManager) importLegacyHTTP01Cache() {
	if m.config.CachePath == "" {
		return
	}

	dir := filepath.Join(m.config.CachePath, legacyHTTP01CacheDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("Unable to read the legacy certificate cache", "path", dir, "error", err)
		}
		return
	}

	imported, skipped, failed := 0, 0, 0

	for _, entry := range entries {
		if entry.IsDir() || !isLegacyCertificateEntry(entry.Name()) {
			skipped++
			continue
		}

		adopted, err := m.importLegacyCertificate(filepath.Join(dir, entry.Name()))
		switch {
		case err != nil:
			slog.Warn("Unable to import a legacy certificate", "entry", entry.Name(), "error", err)
			failed++
		case adopted:
			imported++
		default:
			skipped++
		}
	}

	if imported == 0 && failed == 0 {
		return
	}

	slog.Info("Imported certificates from the legacy certificate cache",
		"path", dir, "imported", imported, "skipped", skipped, "failed", failed)

	// Only once everything usable has been copied into the manager's own layout
	// -- a partial import keeps the source, so nothing is lost to a bad read.
	if failed > 0 {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		slog.Warn("Unable to remove the legacy certificate cache", "path", dir, "error", err)
		return
	}
	slog.Info("Removed the legacy certificate cache", "path", dir)
}

// isLegacyCertificateEntry filters an autocert DirCache listing down to
// certificate entries. autocert also parks its account key and its in-flight
// challenge tokens there, and marks non-certificate entries with a "+" suffix
// ("acme_account+key", "<token>+http-01") -- except "<domain>+rsa", which is
// the RSA variant of a certificate we already import under its bare name.
func isLegacyCertificateEntry(name string) bool {
	return !strings.HasPrefix(name, ".") && !strings.Contains(name, "+")
}

// importLegacyCertificate reads one autocert cache entry -- a private key PEM
// block followed by the certificate chain -- and adopts it. It reports whether
// the certificate was worth keeping; an expired one is not.
func (m *SANCertManager) importLegacyCertificate(path string) (bool, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	keyPEM, certPEM, err := splitLegacyCacheEntry(blob)
	if err != nil {
		return false, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, err
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return false, err
	}

	// Anything already inside the replacement window would be re-ordered
	// immediately anyway, so importing it buys nothing.
	if time.Until(leaf.NotAfter) <= 24*time.Hour {
		return false, nil
	}

	domains := leaf.DNSNames
	if len(domains) == 0 {
		return false, nil
	}

	if _, err := m.adoptCertificate(&certificate.Resource{
		Domain:      domains[0],
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}, sortedCopy(domains)); err != nil {
		return false, err
	}

	return true, nil
}

// splitLegacyCacheEntry separates an autocert cache blob into its private key
// and its certificate chain. autocert writes the key first, then the chain.
func splitLegacyCacheEntry(blob []byte) (keyPEM, certPEM []byte, err error) {
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			keyPEM = append(keyPEM, pem.EncodeToMemory(block)...)
			continue
		}
		if block.Type == "CERTIFICATE" {
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		}
	}

	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return nil, nil, ErrCertNotFound
	}

	return keyPEM, certPEM, nil
}
