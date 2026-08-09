package server

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"syscall"
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
	summary.Warnings = archive.warningTexts()

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
		if err := writeFileStaged(filepath.Join(opts.Paths.CertsPath, acmeUserFile), archive.accountKey); err != nil {
			return summary, fmt.Errorf("failed to restore the ACME account key: %w", err)
		}
		summary.AccountKeyRestored = true
	}

	if archive.dynamicDomains != nil {
		if err := writeFileStaged(opts.Paths.DynamicDomainsStatePath, archive.dynamicDomains); err != nil {
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

	// A forced restore over an existing store must not let a leftover target
	// directory answer for a state-referenced certificate the archive itself
	// does not hold -- the "will re-order" warning would instead silently
	// revive whatever pair the old store had under that identifier. This runs
	// after the state commit on purpose: a restore that fails mid-way leaves
	// the OLD store's files intact rather than an old state file pointing at
	// deleted directories.
	if err := removeStaleCertDirs(opts.Paths.CertsPath, archive); err != nil {
		return summary, err
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
	report.Warnings = archive.warningTexts()

	return report, nil
}

// removeStaleCertDirs deletes target directories for certificates the
// restored state references but the archive does not hold, so those domains
// actually re-order instead of serving whatever the old store left behind.
func removeStaleCertDirs(certsPath string, archive certStoreArchive) error {
	removed := 0
	for _, id := range slices.Sorted(maps.Keys(archive.state.Certificates)) {
		dir := sanitizeFilename(id)
		if _, ok := archive.certs[dir]; ok {
			continue
		}

		// validateManagerState already rejects identifiers that do not name a
		// safe directory; this is the last line of defense in front of an
		// os.RemoveAll that must never resolve outside certsPath.
		if dir == "" || dir == "." || dir == ".." {
			return fmt.Errorf("refusing to remove the unsafe certificate directory for %q", id)
		}

		if err := os.RemoveAll(filepath.Join(certsPath, dir)); err != nil {
			return fmt.Errorf("failed to remove the stale certificate directory for %s: %w", id, err)
		}
		removed++
	}

	// Commit the unlinks: without a directory sync, a crash after the restore
	// reported success could resurrect a stale directory and undo the
	// "missing certificate re-orders" behavior the warnings promised.
	if removed > 0 {
		if err := syncDir(certsPath); err != nil {
			return fmt.Errorf("failed to sync the certificate directory: %w", err)
		}
	}

	return nil
}

// syncDir fsyncs a directory so renames and unlinks inside it survive power
// loss; only a filesystem that cannot sync a directory is excused.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

// writeFileStaged writes a file through a uniquely named same-directory temp
// file and a rename, so an interrupted restore never leaves the target
// truncated, a pre-planted path cannot redirect the write, and a pre-existing
// temp file cannot lend the private key its old permissions. The temp pattern
// is short and fixed so a near-limit destination basename cannot push it past
// the filesystem's component length. The directory is synced after the
// rename, so a restore that reported success survives power loss.
func writeFileStaged(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".kamal-proxy-restore-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := file.Name()

	err = func() error {
		if err := file.Chmod(0600); err != nil {
			return err
		}
		if _, err := file.Write(data); err != nil {
			return err
		}
		return file.Sync()
	}()
	if err != nil {
		file.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := file.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return syncDir(filepath.Dir(path))
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
