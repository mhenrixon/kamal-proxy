package server

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

	state, files, err := collectStateEntry(paths.ACMEStatePath, &summary)
	if err != nil {
		return summary, err
	}

	certFiles, err := collectCertsEntries(paths.CertsPath, state, &summary)
	if err != nil {
		return summary, err
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

	if err := writeCertArchive(outputPath, files); err != nil {
		return summary, err
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
// A directory with only half the pair is skipped with a warning: restoring it
// would leave a certificate the manager cannot load.
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

	return pair, true
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
// temp file and renamed into place so a partial write never looks like a valid
// backup. The archive holds private keys: it is created with mode 0600.
func writeCertArchive(outputPath string, files []archiveFile) error {
	tmpPath := outputPath + ".tmp"

	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create the archive: %w", err)
	}

	err = func() error {
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
		return gz.Close()
	}()
	if err != nil {
		file.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write the archive: %w", err)
	}

	if err := file.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write the archive: %w", err)
	}

	if err := os.Rename(tmpPath, outputPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize the archive: %w", err)
	}

	return nil
}
