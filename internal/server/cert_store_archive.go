package server

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
)

// maxCertArchiveBytes caps how much an archive may decompress to, and
// maxCertArchiveEntries caps how many entries it may hold (zero-length entries
// cost no payload bytes, so a byte cap alone would not bound the tar walk).
// The whole estate of a 1,000-domain fleet is a few megabytes across a few
// thousand entries; anything near these limits is not a certificate backup.
const (
	maxCertArchiveBytes   = 512 << 20
	maxCertArchiveEntries = 100_000
)

// archiveCertPair is one certificate directory from an archive, parsed and
// validated.
type archiveCertPair struct {
	certPEM []byte
	keyPEM  []byte
	leaf    *x509.Certificate
}

// certStoreArchive is a fully read and validated certificate store archive.
// Reading never touches the store: verification and restore share this.
type certStoreArchive struct {
	state    managerState
	hasState bool

	accountKey     []byte
	dynamicDomains []byte

	// certs is keyed by the certificate's directory name (the sanitized
	// certificate identifier).
	certs map[string]archiveCertPair

	warnings []string
}

// readCertStoreArchive reads and validates an exported certificate store
// archive. Structural problems -- traversal-shaped or unexpected entry names,
// torn certificate pairs, an unparseable or inconsistent state file -- are
// errors: a backup that fails here cannot be trusted to restore. An expired
// certificate is not an error; a faithful backup of an expired certificate is
// still a backup.
func readCertStoreArchive(archivePath string) (certStoreArchive, error) {
	archive := certStoreArchive{certs: map[string]archiveCertPair{}}

	file, err := os.Open(archivePath)
	if err != nil {
		return archive, fmt.Errorf("failed to open the archive: %w", err)
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return archive, fmt.Errorf("failed to read the archive %s: %w", archivePath, err)
	}
	defer gz.Close()

	rawCerts := map[string]map[string][]byte{}
	entryCount := 0
	var totalBytes int64

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return archive, fmt.Errorf("failed to read the archive %s: %w", archivePath, err)
		}

		entryCount++
		if entryCount > maxCertArchiveEntries {
			return archive, fmt.Errorf("refusing the archive %s: more than %d entries", archivePath, maxCertArchiveEntries)
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return archive, fmt.Errorf("refusing archive entry %q: only regular files belong in a certificate archive", header.Name)
		}

		totalBytes += header.Size
		if totalBytes > maxCertArchiveBytes {
			return archive, fmt.Errorf("refusing the archive %s: it decompresses beyond %d bytes", archivePath, int64(maxCertArchiveBytes))
		}

		data, err := io.ReadAll(io.LimitReader(tr, maxCertArchiveBytes))
		if err != nil {
			return archive, fmt.Errorf("failed to read the archive entry %q: %w", header.Name, err)
		}

		if err := archive.placeEntry(header.Name, data, rawCerts); err != nil {
			return archive, err
		}
	}

	if entryCount == 0 {
		return archive, fmt.Errorf("the archive %s is empty", archivePath)
	}

	if err := archive.assembleCertPairs(rawCerts); err != nil {
		return archive, err
	}

	if err := archive.validate(); err != nil {
		return archive, err
	}

	return archive, nil
}

// placeEntry routes one archive entry to its slot, refusing any name the
// exporter would never write -- which is also what keeps a hostile archive
// from writing outside the store.
func (a *certStoreArchive) placeEntry(name string, data []byte, rawCerts map[string]map[string][]byte) error {
	if name != path.Clean(name) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "..") {
		return fmt.Errorf("refusing archive entry %q: not a certificate store path", name)
	}

	switch name {
	case archiveStateEntry:
		if err := json.Unmarshal(data, &a.state); err != nil {
			return fmt.Errorf("the archive's %s does not parse: %w", archiveStateEntry, err)
		}
		a.hasState = true
		return nil
	case archiveAccountKeyEntry:
		a.accountKey = data
		return nil
	case archiveDynamicDomainsEntry:
		a.dynamicDomains = data
		return nil
	}

	if rest, ok := strings.CutPrefix(name, archiveCertsPrefix); ok {
		dir, base, found := strings.Cut(rest, "/")
		// The directory must already be in the sanitized form the exporter
		// writes: two spellings that sanitize to the same on-disk path would
		// otherwise silently overwrite each other during a restore.
		if found && dir != "" && dir == sanitizeFilename(dir) &&
			(base == "cert.pem" || base == "key.pem") && !strings.Contains(base, "/") {
			if rawCerts[dir] == nil {
				rawCerts[dir] = map[string][]byte{}
			}
			rawCerts[dir][base] = data
			return nil
		}
	}

	return fmt.Errorf("unexpected archive entry %q: not part of a certificate store", name)
}

// assembleCertPairs pairs and parses every certificate directory. Half a pair
// or an unparseable pair is a torn backup, not a skippable entry.
func (a *certStoreArchive) assembleCertPairs(rawCerts map[string]map[string][]byte) error {
	for _, dir := range slices.Sorted(maps.Keys(rawCerts)) {
		files := rawCerts[dir]

		for _, base := range []string{"cert.pem", "key.pem"} {
			if _, ok := files[base]; !ok {
				return fmt.Errorf("the archived certificate %s is missing %s", dir, base)
			}
		}

		certPEM, keyPEM := files["cert.pem"], files["key.pem"]
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("the archived certificate %s does not parse: %w", dir, err)
		}
		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("the archived certificate %s has an invalid leaf: %w", dir, err)
		}

		a.certs[dir] = archiveCertPair{certPEM: certPEM, keyPEM: keyPEM, leaf: leaf}
	}

	return nil
}

// validate cross-checks the state file against the archived certificates and
// discards an account key that could not carry the ACME identity forward.
func (a *certStoreArchive) validate() error {
	a.checkAccountKey()

	if !a.hasState {
		if len(a.certs) > 0 {
			return errors.New("the archive contains certificates but no acme.state; it cannot restore a working store")
		}
		return nil
	}

	if err := validateManagerState(a.state); err != nil {
		return fmt.Errorf("the archive's %s is not trustworthy: %w", archiveStateEntry, err)
	}

	for _, id := range slices.Sorted(maps.Keys(a.state.Certificates)) {
		record := a.state.Certificates[id]

		pair, ok := a.certs[sanitizeFilename(id)]
		if !ok {
			// A state-referenced certificate missing from the archive restores
			// to the same place loadState puts a missing file: the domain
			// re-orders. Warn, don't fail -- the export warned identically.
			a.warnings = append(a.warnings,
				fmt.Sprintf("certificate %s is referenced by the state file but missing from the archive; its domains will re-order after a restore", id))
			continue
		}

		// The certificate must actually be what the state record says it is:
		// restoring a record whose leaf names other hosts or expired earlier
		// would have the manager serving the wrong certificate, or keeping it
		// past its real expiry.
		for _, domain := range record.Domains {
			if !slices.Contains(pair.leaf.DNSNames, domain) {
				return fmt.Errorf("the archived certificate %s does not cover %q, which its state record claims", id, domain)
			}
		}
		// Compared at second precision: x509 validity has no sub-second field,
		// while state metadata written from other sources may.
		if !record.NotAfter.Truncate(time.Second).Equal(pair.leaf.NotAfter.Truncate(time.Second)) {
			return fmt.Errorf("the archived certificate %s expires %s, but its state record says %s",
				id, pair.leaf.NotAfter.Format(time.RFC3339), record.NotAfter.Format(time.RFC3339))
		}
	}

	return nil
}

// checkAccountKey drops an account key entry that does not hold usable key
// material, with a warning: restoring it would make the next boot silently
// register a fresh ACME account while the operator believes the identity was
// preserved. The estate's certificates still restore.
func (a *certStoreArchive) checkAccountKey() {
	if a.accountKey == nil {
		return
	}

	var user acmeUser
	if err := json.Unmarshal(a.accountKey, &user); err != nil {
		a.warnings = append(a.warnings,
			fmt.Sprintf("the archived ACME account key does not parse and will not be restored; the next boot will register a fresh account: %v", err))
		a.accountKey = nil
		return
	}

	if _, err := certcrypto.ParsePEMPrivateKey(user.KeyPEM); err != nil {
		a.warnings = append(a.warnings,
			fmt.Sprintf("the archived ACME account key holds no usable private key and will not be restored; the next boot will register a fresh account: %v", err))
		a.accountKey = nil
	}
}

// validateManagerState checks the invariants a healthy manager always
// maintains: both maps present, no null certificate records, no domain mapped
// to a certificate that is not there. Shared by the Traefik importer (before
// merging into an existing state file) and the archive reader.
func validateManagerState(state managerState) error {
	if state.Certificates == nil || state.DomainMap == nil {
		return errors.New("it does not look like a certificate state file")
	}

	for id, cert := range state.Certificates {
		if cert == nil {
			return fmt.Errorf("certificate %q is null", id)
		}
	}

	for domain, id := range state.DomainMap {
		if _, ok := state.Certificates[id]; !ok {
			return fmt.Errorf("domain %q references a missing certificate %q", domain, id)
		}
	}

	return nil
}
