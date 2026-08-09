package server

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// The certificate store archive mirrors the data directory layout, so a
// restore is a faithful extraction: acme.state and dynamic-domains.state at
// the root, the account key and one directory per certificate under certs/.
const (
	archiveStateEntry          = "acme.state"
	archiveDynamicDomainsEntry = "dynamic-domains.state"
	archiveCertsPrefix         = "certs/"
	archiveAccountKeyEntry     = archiveCertsPrefix + acmeUserFile

	acmeUserFile = "acme_user.json"
)

// ErrCertStoreEmpty reports an export attempt against a store with nothing in
// it. Failing loudly beats a cron job faithfully archiving nothing.
var ErrCertStoreEmpty = errors.New("certificate store is empty; nothing to export")

// CertStorePaths names the on-disk pieces of the certificate estate.
type CertStorePaths struct {
	// CertsPath is the certificate cache directory, which also holds the ACME
	// account key (Config.CertificatePath()).
	CertsPath string

	// ACMEStatePath is the certificate manager's state file (Config.ACMEStatePath()).
	ACMEStatePath string

	// DynamicDomainsStatePath is the dynamic domain manager's state file
	// (Config.DynamicDomainsStatePath()).
	DynamicDomainsStatePath string
}

// CertsExportSummary reports what an export captured. Warnings flag pieces of
// the store that were skipped or inconsistent without aborting the export.
type CertsExportSummary struct {
	Certificates int      `json:"certificates"`
	Domains      int      `json:"domains"`
	Warnings     []string `json:"warnings,omitempty"`
}

// archiveFile is one file staged for the archive.
type archiveFile struct {
	name    string
	data    []byte
	modTime time.Time
}

// ExportStore writes a consistent snapshot of the certificate store while
// holding the store's disk-write lock, so no concurrent issuance, renewal, or
// removal tears the archive.
func (m *SANCertManager) ExportStore(paths CertStorePaths, outputPath string) (CertsExportSummary, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	return ExportCertificateStore(paths, outputPath)
}

// ExportCertificateStore archives the certificate estate -- state file,
// certificates with their private keys, ACME account key, and dynamic domain
// state -- into a gzipped tarball written atomically with mode 0600.
//
// Callers running against a live proxy must hold the store's disk-write lock
// (SANCertManager.ExportStore does); running offline against a stopped data
// dir needs no lock.
func ExportCertificateStore(paths CertStorePaths, outputPath string) (CertsExportSummary, error) {
	summary := CertsExportSummary{}

	// The write below uses this same resolved path, so the validated path and
	// the written path cannot diverge through a parent symlink swapped after
	// the check.
	outputPath, err := safeOutputPath(paths, outputPath)
	if err != nil {
		return summary, err
	}

	state, files, err := collectStateEntry(paths.ACMEStatePath, &summary)
	if err != nil {
		return summary, err
	}
	hasState := len(files) > 0

	certFiles, err := collectCertsEntries(paths.CertsPath, state, &summary)
	if err != nil {
		return summary, err
	}

	// Certificates without a state file cannot restore into a working store
	// (the state is the estate's index), and the archive reader rejects that
	// shape -- fail the backup now rather than hand over an unrestorable one.
	// The account key alone is not a certificate: a fresh estate that has only
	// registered an account still gets its backup.
	certsWithoutState := slices.ContainsFunc(certFiles, func(file archiveFile) bool {
		return file.name != archiveAccountKeyEntry
	})
	if !hasState && certsWithoutState {
		return summary, fmt.Errorf("the certificate store has certificates but no state file at %s; refusing to export an unrestorable archive", paths.ACMEStatePath)
	}
	files = append(files, certFiles...)

	if dynamic, ok := collectOptionalJSON(paths.DynamicDomainsStatePath, archiveDynamicDomainsEntry, &summary); ok {
		files = append(files, dynamic)
	}

	if len(files) == 0 {
		return summary, ErrCertStoreEmpty
	}

	slices.SortFunc(files, func(a, b archiveFile) int {
		return strings.Compare(a.name, b.name)
	})

	readerWarnings, err := writeCertArchive(outputPath, files)
	if err != nil {
		return summary, err
	}

	// The staged-archive verification sees things the collection pass cannot
	// -- an account key the reader would refuse to restore, for one. Its
	// missing-certificate warnings are skipped: each of those was already
	// reported above from the disk side.
	for _, warning := range readerWarnings {
		if !strings.Contains(warning, "missing from the archive") {
			summary.Warnings = append(summary.Warnings, warning)
		}
	}

	return summary, nil
}

// collectStateEntry reads and validates acme.state. A store whose index is
// unreadable produces backups that cannot restore, so unlike every other file
// this one aborts the export when it exists but does not parse.
func collectStateEntry(path string, summary *CertsExportSummary) (managerState, []archiveFile, error) {
	state := managerState{}

	data, modTime, err := readFileWithModTime(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil, nil
		}
		return state, nil, fmt.Errorf("failed to read %s: %w", filepath.Base(path), err)
	}

	if err := json.Unmarshal(data, &state); err != nil {
		return state, nil, fmt.Errorf("refusing to export the unreadable state file %s: %w", path, err)
	}

	// An inconsistent state file exports into an archive the verifier and the
	// restore path reject; fail the backup while the operator can still fix
	// the live store.
	if err := validateManagerState(state); err != nil {
		return state, nil, fmt.Errorf("refusing to export the state file %s: %w", path, err)
	}

	summary.Certificates = len(state.Certificates)
	summary.Domains = len(state.DomainMap)

	return state, []archiveFile{{name: archiveStateEntry, data: data, modTime: modTime}}, nil
}

// collectCertsEntries walks the certificate cache directory, capturing the
// account key and every complete certificate pair, and warning about anything
// else it finds -- including certificates the state file references but the
// disk no longer holds.
func collectCertsEntries(certsPath string, state managerState, summary *CertsExportSummary) ([]archiveFile, error) {
	files := []archiveFile{}

	entries, err := os.ReadDir(certsPath)
	if err != nil {
		if os.IsNotExist(err) {
			warnMissingStateCerts(certsPath, state, summary)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read the certificate directory %s: %w", certsPath, err)
	}

	for _, entry := range entries {
		name := entry.Name()

		switch {
		case !entry.IsDir() && name == acmeUserFile:
			if file, ok := collectOptionalJSON(filepath.Join(certsPath, name), archiveAccountKeyEntry, summary); ok {
				files = append(files, file)
			}
		case entry.IsDir() && name == legacyHTTP01CacheDir:
			summary.Warnings = append(summary.Warnings,
				fmt.Sprintf("legacy %s cache is not exported: start the proxy once so it is adopted into the store first", legacyHTTP01CacheDir))
		case entry.IsDir():
			pair, ok := collectCertPair(certsPath, name, summary)
			if !ok {
				continue
			}
			files = append(files, pair...)
		default:
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("not exported: unexpected file %s", filepath.Join("certs", name)))
		}
	}

	warnMissingStateCerts(certsPath, state, summary)

	return files, nil
}

// collectCertPair captures one certificate directory's cert.pem and key.pem.
// A directory with only half the pair, or a pair that does not parse, is
// skipped with a warning: the strict archive reader would reject the whole
// archive over it, and a certificate the manager cannot load is not worth
// failing the backup for.
func collectCertPair(certsPath, dir string, summary *CertsExportSummary) ([]archiveFile, bool) {
	pair := make([]archiveFile, 0, 2)

	for _, name := range []string{"cert.pem", "key.pem"} {
		data, modTime, err := readFileWithModTime(filepath.Join(certsPath, dir, name))
		if err != nil {
			summary.Warnings = append(summary.Warnings,
				fmt.Sprintf("not exported: certificate %s is missing %s", dir, name))
			return nil, false
		}
		pair = append(pair, archiveFile{name: archiveCertsPrefix + dir + "/" + name, data: data, modTime: modTime})
	}

	if _, err := tls.X509KeyPair(pair[0].data, pair[1].data); err != nil {
		summary.Warnings = append(summary.Warnings,
			fmt.Sprintf("not exported: certificate %s does not parse: %v", dir, err))
		return nil, false
	}

	return pair, true
}

// safeOutputPath refuses an output path that would overwrite part of the
// store being exported -- writing the archive over acme.state completes the
// export and then destroys the live state it archived -- and returns the
// symlink-resolved path the caller must write to, so the validated path and
// the written path are one and the same.
//
// Two layers: string comparison on resolved paths, then filesystem identity
// (os.SameFile) against the output's existing ancestors, which also holds on
// case-insensitive filesystems where two spellings name one file.
func safeOutputPath(paths CertStorePaths, outputPath string) (string, error) {
	output, err := resolveForComparison(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve the output path: %w", err)
	}

	for _, statePath := range []string{paths.ACMEStatePath, paths.DynamicDomainsStatePath} {
		if resolved, err := resolveForComparison(statePath); err == nil && resolved == output {
			return "", fmt.Errorf("refusing to write the archive over the store's own %s", filepath.Base(statePath))
		}
		if sameExistingFile(statePath, output) {
			return "", fmt.Errorf("refusing to write the archive over the store's own %s", filepath.Base(statePath))
		}
	}

	certsResolved, err := resolveForComparison(paths.CertsPath)
	if err == nil && (output == certsResolved || strings.HasPrefix(output, certsResolved+string(filepath.Separator))) {
		return "", fmt.Errorf("refusing to write the archive inside the certificate directory %s", paths.CertsPath)
	}
	if certsInfo, err := os.Stat(paths.CertsPath); err == nil {
		for current := output; ; {
			if info, err := os.Stat(current); err == nil && os.SameFile(certsInfo, info) {
				return "", fmt.Errorf("refusing to write the archive inside the certificate directory %s", paths.CertsPath)
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}

	return output, nil
}

// sameExistingFile reports whether two paths name the same existing file.
func sameExistingFile(a, b string) bool {
	infoA, err := os.Stat(a)
	if err != nil {
		return false
	}
	infoB, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(infoA, infoB)
}

// resolveForComparison absolutizes a path and resolves the symlinks in every
// component that exists: the path itself when it does, otherwise its deepest
// existing ancestor, with the non-existing remainder rejoined.
func resolveForComparison(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	remainder := ""
	for current := abs; ; {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(resolved, remainder), nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			return abs, nil
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
	}
}

// warnMissingStateCerts flags certificates the state file references that have
// no files on disk. The restore side treats them the same way loadState does:
// the domain falls through to ordinary provisioning.
func warnMissingStateCerts(certsPath string, state managerState, summary *CertsExportSummary) {
	for _, id := range slices.Sorted(maps.Keys(state.Certificates)) {
		if _, err := os.Stat(filepath.Join(certsPath, sanitizeFilename(id), "cert.pem")); err != nil {
			summary.Warnings = append(summary.Warnings,
				fmt.Sprintf("certificate %s is referenced by the state file but missing on disk; its domains will re-order after a restore", id))
		}
	}
}

// collectOptionalJSON captures a file that must be JSON to be worth restoring.
// A missing file is silently skipped; an unreadable or invalid one degrades to
// a warning, because both the account key and the dynamic domain list are
// rebuilt automatically by a booted proxy.
func collectOptionalJSON(path, entryName string, summary *CertsExportSummary) (archiveFile, bool) {
	data, modTime, err := readFileWithModTime(path)
	if err != nil {
		if !os.IsNotExist(err) {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("not exported: failed to read %s: %v", entryName, err))
		}
		return archiveFile{}, false
	}

	if !json.Valid(data) {
		summary.Warnings = append(summary.Warnings, fmt.Sprintf("not exported: %s is not valid JSON", entryName))
		return archiveFile{}, false
	}

	return archiveFile{name: entryName, data: data, modTime: modTime}, true
}

func readFileWithModTime(path string) ([]byte, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}

	return data, info.ModTime(), nil
}

// writeCertArchive writes the staged files as a gzipped tarball, staged as a
// uniquely named same-directory temp file and renamed into place so a partial
// write never looks like a valid backup and a pre-planted path cannot redirect
// the write. The archive holds private keys: the temp file is created 0600 by
// CreateTemp and chmodded to be certain. It is fsynced before the rename --
// this is a disaster-recovery artifact, "written" has to mean "on disk".
// It returns the warnings the staged-archive verification produced.
func writeCertArchive(outputPath string, files []archiveFile) ([]string, error) {
	file, err := os.CreateTemp(filepath.Dir(outputPath), filepath.Base(outputPath)+".*.tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create the archive: %w", err)
	}
	tmpPath := file.Name()

	err = func() error {
		if err := file.Chmod(0600); err != nil {
			return err
		}

		gz := gzip.NewWriter(file)
		tw := tar.NewWriter(gz)

		for _, entry := range files {
			header := &tar.Header{
				Name:    entry.name,
				Mode:    0600,
				Size:    int64(len(entry.data)),
				ModTime: entry.modTime,
			}
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			if _, err := tw.Write(entry.data); err != nil {
				return err
			}
		}

		if err := tw.Close(); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		return file.Sync()
	}()
	if err != nil {
		file.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to write the archive: %w", err)
	}

	if err := file.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to write the archive: %w", err)
	}

	// Read the staged archive back through the same strict reader verify and
	// restore use, so a published export is restorable by construction -- any
	// disagreement between what was collected and what the reader accepts
	// fails the backup here, not in a disaster.
	staged, err := readCertStoreArchive(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("the staged archive failed verification: %w", err)
	}

	if err := os.Rename(tmpPath, outputPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to finalize the archive: %w", err)
	}

	// Sync the directory so the rename itself survives power loss. Only a
	// filesystem that genuinely does not support syncing a directory is
	// excused; a real failure means the backup's existence is not durable,
	// which a disaster-recovery artifact cannot shrug off.
	dir, err := os.Open(filepath.Dir(outputPath))
	if err != nil {
		return nil, fmt.Errorf("failed to sync the archive's directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, syscall.EINVAL) {
		return nil, fmt.Errorf("failed to sync the archive's directory: %w", err)
	}

	return staged.warnings, nil
}
