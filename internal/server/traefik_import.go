package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// TraefikImportOptions configures an offline import of certificates from a
// Traefik acme.json into the SAN certificate store. It runs against the data
// directory before first boot, so it needs no RPC and no running proxy.
type TraefikImportOptions struct {
	// ACMEPath is the Traefik acme.json to read.
	ACMEPath string

	// Resolver selects a single resolver block by name. Empty imports every
	// resolver, visiting them in sorted order so a domain held by more than one
	// resolver deterministically keeps the last writer's certificate.
	Resolver string

	// CertsPath is the SAN certificate store (Config.CertificatePath()).
	CertsPath string

	// StatePath is the manager state file (Config.ACMEStatePath()).
	StatePath string
}

// TraefikImportSummary reports what an import did. Individual skips are not
// errors: only I/O failures or wholly unparseable input abort an import.
type TraefikImportSummary struct {
	Imported         int
	SkippedExpired   int
	SkippedDuplicate int
	FailedToParse    int
	Warnings         []string
}

// Traefik's acme.json layout: one block per certificate resolver, each with an
// Account (not imported -- a fresh registration on first boot is cheap) and a
// list of certificates as base64-wrapped PEM.
type traefikResolver struct {
	Certificates []traefikCertificate `json:"Certificates"`
}

// traefikCertificate keeps certificate and key as strings rather than []byte so
// one corrupt base64 blob fails that entry alone, not the whole file's
// json.Unmarshal.
type traefikCertificate struct {
	Domain      traefikDomain `json:"domain"`
	Certificate string        `json:"certificate"`
	Key         string        `json:"key"`
}

type traefikDomain struct {
	Main string   `json:"main"`
	SANs []string `json:"sans"`
}

// ImportTraefikCertificates seeds the SAN certificate store from a Traefik
// acme.json, so a fleet cut over from Traefik serves TLS immediately instead
// of hard-failing every handshake while the whole estate is re-issued under
// the issuance rate limit.
//
// Imported certificates become ordinary managed certificates: the renewal
// manager rotates them on schedule, re-issuing under whichever challenge the
// proxy is configured for. SAN groupings from the source are preserved as-is
// until natural renewal regroups them.
//
// A domain already mapped in an existing state file keeps its certificate if
// that certificate outlives the imported one.
func ImportTraefikCertificates(opts TraefikImportOptions) (TraefikImportSummary, error) {
	summary := TraefikImportSummary{}

	data, err := os.ReadFile(opts.ACMEPath)
	if err != nil {
		return summary, fmt.Errorf("failed to read the Traefik acme file: %w", err)
	}

	var resolvers map[string]traefikResolver
	if err := json.Unmarshal(data, &resolvers); err != nil {
		return summary, fmt.Errorf("failed to parse the Traefik acme file %s: %w", opts.ACMEPath, err)
	}

	names := slices.Sorted(maps.Keys(resolvers))
	if opts.Resolver != "" {
		if _, ok := resolvers[opts.Resolver]; !ok {
			return summary, fmt.Errorf("resolver %q not found in %s (found: %s)",
				opts.Resolver, opts.ACMEPath, strings.Join(names, ", "))
		}
		names = []string{opts.Resolver}
	}

	state, err := loadStateForImport(opts.StatePath)
	if err != nil {
		return summary, err
	}

	imp := &traefikImport{
		opts:       opts,
		state:      state,
		importedBy: map[string]string{},
		now:        time.Now(),
	}

	for _, name := range names {
		for _, entry := range resolvers[name].Certificates {
			if err := imp.importEntry(name, entry, &summary); err != nil {
				return summary, err
			}
		}
	}

	state.SavedAt = time.Now()
	if err := writeManagerStateFile(opts.StatePath, state); err != nil {
		return summary, fmt.Errorf("failed to write certificate state: %w", err)
	}

	return summary, nil
}

// traefikImport carries the merge state of one import run.
type traefikImport struct {
	opts  TraefikImportOptions
	state managerState

	// importedBy records which resolver wrote each domain during THIS run, so a
	// contested domain goes to the last writer -- unlike a domain from the
	// pre-existing state, which is only replaced by a longer-lived certificate.
	importedBy map[string]string

	now time.Time
}

// importEntry adopts one source certificate. Entry-level problems are counted
// in the summary and never abort the run; only I/O failures return an error.
func (imp *traefikImport) importEntry(resolver string, entry traefikCertificate, summary *TraefikImportSummary) error {
	leaf, certPEM, keyPEM, err := parseTraefikEntry(entry)
	if err != nil {
		summary.FailedToParse++
		summary.Warnings = append(summary.Warnings,
			fmt.Sprintf("resolver %s: failed to parse the entry for %q: %v", resolver, entry.Domain.Main, err))
		return nil
	}

	// Only certificates outside their validity window are refused. A nearly
	// expired one (inside the manager's 24-hour replacement window) still
	// imports: a deploy-registered domain re-orders on its first handshake
	// either way, so importing loses nothing, while a dynamic domain keeps
	// serving the certificate while its renewal runs.
	if imp.now.After(leaf.NotAfter) || imp.now.Before(leaf.NotBefore) {
		summary.SkippedExpired++
		return nil
	}

	domains := sortedCopy(leaf.DNSNames)
	winners := imp.claimDomains(resolver, domains, leaf.NotAfter, summary)
	if len(winners) == 0 {
		summary.SkippedDuplicate++
		return nil
	}

	certID := sanCertID(domains)
	if err := writeCertificateFiles(imp.opts.CertsPath, certID, certPEM, keyPEM); err != nil {
		return fmt.Errorf("failed to store the certificate for %q: %w", domains[0], err)
	}

	imp.state.Certificates[certID] = &ManagedCert{
		Identifier: certID,
		Domains:    domains,
		NotAfter:   leaf.NotAfter,
	}
	for _, domain := range winners {
		imp.state.DomainMap[domain] = certID
		imp.importedBy[domain] = resolver

		if strings.HasPrefix(domain, "*.") {
			summary.Warnings = append(summary.Warnings,
				fmt.Sprintf("%s is a wildcard: renewal requires a DNS-01 provider to be configured", domain))
		}
	}

	summary.Imported++
	return nil
}

// claimDomains decides which of an entry's domains it gets to map: a domain
// written earlier in this run goes to the last writer (with a warning naming
// both resolvers), while a domain from the pre-existing state is kept when its
// certificate outlives the imported one.
func (imp *traefikImport) claimDomains(resolver string, domains []string, notAfter time.Time, summary *TraefikImportSummary) []string {
	winners := make([]string, 0, len(domains))

	for _, domain := range domains {
		if earlier, ok := imp.importedBy[domain]; ok {
			summary.Warnings = append(summary.Warnings,
				fmt.Sprintf("%s appears in more than one resolver: keeping the certificate from %q over %q",
					domain, resolver, earlier))
			winners = append(winners, domain)
			continue
		}

		if existingID, ok := imp.state.DomainMap[domain]; ok {
			if existing := imp.state.Certificates[existingID]; existing != nil && !existing.NotAfter.Before(notAfter) {
				continue
			}
		}

		winners = append(winners, domain)
	}

	return winners
}

// parseTraefikEntry unwraps one certificate entry -- base64 around PEM -- and
// parses its leaf. The leaf's DNS names are the imported domain set; the
// domain metadata in the JSON is only advisory.
func parseTraefikEntry(entry traefikCertificate) (*x509.Certificate, []byte, []byte, error) {
	certPEM, err := base64.StdEncoding.DecodeString(entry.Certificate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid certificate encoding: %w", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(entry.Key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid key encoding: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid key pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid leaf certificate: %w", err)
	}

	if len(leaf.DNSNames) == 0 {
		return nil, nil, nil, fmt.Errorf("certificate names no domains")
	}

	return leaf, certPEM, keyPEM, nil
}

// writeCertificateFiles stores a certificate in the SAN manager's layout, the
// same paths saveCertificate uses. Both files are staged as temp files before
// either is renamed into place, so a failed write never touches an existing
// pair. A crash exactly between the two renames can still leave a mismatched
// pair: loadState then leaves that certificate unloaded (a nil Certificate)
// and its domains fall through to ordinary provisioning, so the cost is a
// re-order, not an unrecoverable state -- and re-running the import rewrites
// both files.
func writeCertificateFiles(certsPath, certID string, certPEM, keyPEM []byte) error {
	certDir := filepath.Join(certsPath, sanitizeFilename(certID))
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}

	files := []struct {
		name string
		data []byte
	}{
		{"cert.pem", certPEM},
		{"key.pem", keyPEM},
	}

	// Stage everything first: a failed or partial write aborts before any
	// rename, leaving an existing pair untouched.
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(certDir, file.name+".tmp"), file.data, 0600); err != nil {
			return err
		}
	}

	for _, file := range files {
		path := filepath.Join(certDir, file.name)
		if err := os.Rename(path+".tmp", path); err != nil {
			return err
		}
	}

	return nil
}

// loadStateForImport reads an existing state file so the import merges rather
// than clobbers. A state file that exists but cannot be parsed -- or parses
// but does not look like manager state -- aborts the import: overwriting it
// could orphan live certificates. writeManagerStateFile always emits both
// maps, so requiring them rejects nothing legitimate.
func loadStateForImport(path string) (managerState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return managerState{
				Certificates: map[string]*ManagedCert{},
				DomainMap:    map[string]string{},
			}, nil
		}
		return managerState{}, fmt.Errorf("failed to read the existing certificate state: %w", err)
	}

	var state managerState
	if err := json.Unmarshal(data, &state); err != nil {
		return managerState{}, fmt.Errorf("refusing to overwrite the unreadable certificate state %s: %w", path, err)
	}

	if state.Certificates == nil || state.DomainMap == nil {
		return managerState{}, fmt.Errorf("refusing to overwrite %s: it does not look like a certificate state file", path)
	}

	// A healthy manager never persists null records or dangling mappings
	// (removeCertificate unmaps domains in the same critical section), so
	// either one means the file is not trustworthy enough to merge into.
	for id, cert := range state.Certificates {
		if cert == nil {
			return managerState{}, fmt.Errorf("refusing to overwrite %s: certificate %q is null", path, id)
		}
	}
	for domain, id := range state.DomainMap {
		if _, ok := state.Certificates[id]; !ok {
			return managerState{}, fmt.Errorf("refusing to overwrite %s: domain %q references a missing certificate %q", path, domain, id)
		}
	}

	return state, nil
}
