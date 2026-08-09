package server

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// ErrCertStoreNotEmpty reports a restore attempt over a store that already
// holds something. Overwriting live certificate state is an explicit decision,
// not a default.
var ErrCertStoreNotEmpty = errors.New("the certificate store is not empty")

// CertStoreRestoreOptions configures an offline restore of a certificate store
// archive into a data directory. Like the Traefik import, it runs against a
// stopped proxy -- the runbook is stop, restore, start.
type CertStoreRestoreOptions struct {
	// ArchivePath is the archive to restore from.
	ArchivePath string

	// Paths is the target store (Config.CertStorePaths()).
	Paths CertStorePaths

	// Force overwrites a non-empty store. Existing certificate directories the
	// archive does not reference are left on disk but unreferenced by the
	// restored state.
	Force bool
}

// CertsRestoreSummary reports what a restore wrote.
type CertsRestoreSummary struct {
	Certificates           int
	Domains                int
	AccountKeyRestored     bool
	DynamicDomainsRestored bool
	Warnings               []string
}

// ArchiveCertInfo describes one certificate found in an archive, read from the
// certificate itself rather than the state file.
type ArchiveCertInfo struct {
	Identifier string
	Domains    []string
	NotAfter   time.Time
}

// CertArchiveReport is what verification learned about an archive.
type CertArchiveReport struct {
	Certificates      []ArchiveCertInfo
	DomainMappings    int
	HasAccountKey     bool
	HasDynamicDomains bool
	Warnings          []string
}

// RestoreCertificateStore restores an exported archive into a data directory,
// writing certificates through the same staged path the importers and the live
// manager use. The state file is written last, so an interrupted restore never
// leaves a state file naming certificates that were not written yet.
func RestoreCertificateStore(opts CertStoreRestoreOptions) (CertsRestoreSummary, error) {
	summary := CertsRestoreSummary{}

	archive, err := readCertStoreArchive(opts.ArchivePath)
	if err != nil {
		return summary, err
	}
	summary.Warnings = archive.warnings

	if !opts.Force {
		if occupant := certStoreOccupant(opts.Paths); occupant != "" {
			return summary, fmt.Errorf("%w: %s exists (use --force to overwrite)", ErrCertStoreNotEmpty, occupant)
		}
	}

	for _, dir := range slices.Sorted(maps.Keys(archive.certs)) {
		pair := archive.certs[dir]
		if err := writeCertificateFiles(opts.Paths.CertsPath, dir, pair.certPEM, pair.keyPEM); err != nil {
			return summary, fmt.Errorf("failed to restore the certificate %s: %w", dir, err)
		}
	}

	if archive.accountKey != nil {
		if err := os.MkdirAll(opts.Paths.CertsPath, 0700); err != nil {
			return summary, fmt.Errorf("failed to create the certificate directory: %w", err)
		}
		if err := os.WriteFile(filepath.Join(opts.Paths.CertsPath, acmeUserFile), archive.accountKey, 0600); err != nil {
			return summary, fmt.Errorf("failed to restore the ACME account key: %w", err)
		}
		summary.AccountKeyRestored = true
	}

	if archive.dynamicDomains != nil {
		if err := os.WriteFile(opts.Paths.DynamicDomainsStatePath, archive.dynamicDomains, 0600); err != nil {
			return summary, fmt.Errorf("failed to restore the dynamic domains state: %w", err)
		}
		summary.DynamicDomainsRestored = true
	}

	if archive.hasState {
		if err := writeManagerStateFile(opts.Paths.ACMEStatePath, archive.state); err != nil {
			return summary, fmt.Errorf("failed to restore the certificate state: %w", err)
		}
		summary.Certificates = len(archive.state.Certificates)
		summary.Domains = len(archive.state.DomainMap)
	}

	return summary, nil
}

// VerifyCertificateArchive reads an archive the way a restore would -- full
// structural validation, every certificate parsed -- without touching any
// store, and reports what it holds. This is the CI/cron backup check.
func VerifyCertificateArchive(archivePath string) (CertArchiveReport, error) {
	report := CertArchiveReport{}

	archive, err := readCertStoreArchive(archivePath)
	if err != nil {
		return report, err
	}

	// Prefer the state file's identifier for a certificate; a directory the
	// state does not name is reported by its directory name.
	idByDir := map[string]string{}
	for id := range archive.state.Certificates {
		idByDir[sanitizeFilename(id)] = id
	}

	for _, dir := range slices.Sorted(maps.Keys(archive.certs)) {
		pair := archive.certs[dir]

		identifier := idByDir[dir]
		if identifier == "" {
			identifier = dir
		}

		report.Certificates = append(report.Certificates, ArchiveCertInfo{
			Identifier: identifier,
			Domains:    sortedCopy(pair.leaf.DNSNames),
			NotAfter:   pair.leaf.NotAfter,
		})
	}

	report.DomainMappings = len(archive.state.DomainMap)
	report.HasAccountKey = archive.accountKey != nil
	report.HasDynamicDomains = archive.dynamicDomains != nil
	report.Warnings = archive.warnings

	return report, nil
}

// certStoreOccupant names the first thing found occupying the target store, or
// "" when the store is empty. An existing but empty certs directory does not
// count.
func certStoreOccupant(paths CertStorePaths) string {
	if _, err := os.Stat(paths.ACMEStatePath); err == nil {
		return paths.ACMEStatePath
	}

	if _, err := os.Stat(paths.DynamicDomainsStatePath); err == nil {
		return paths.DynamicDomainsStatePath
	}

	if entries, err := os.ReadDir(paths.CertsPath); err == nil && len(entries) > 0 {
		return filepath.Join(paths.CertsPath, entries[0].Name())
	}

	return ""
}
