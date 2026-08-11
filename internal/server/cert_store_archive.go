package server

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ecdsa"
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

	// maxCertArchiveHeaderBytes bounds the decompressed bytes spent on tar
	// headers and their PAX/GNU metadata records, which archive/tar consumes
	// inside Next() before the entry counter can run. 100k plain headers cost
	// ~51MB, so the cap leaves legitimate archives room while a hostile chain
	// of metadata records runs out of budget.
	maxCertArchiveHeaderBytes = 64 << 20
)

// errCertArchiveTooLarge marks the decompressed-size cap being hit mid-read.
var errCertArchiveTooLarge = errors.New("certificate archive decompresses beyond the size limit")

// cappedReader bounds how many bytes may be read through it, failing with
// errCertArchiveTooLarge instead of a bare EOF so the caller can tell a
// too-large archive from a truncated one. A stream that ends exactly at the
// limit is not over it: at the boundary the underlying reader is probed, and
// only actual further data trips the cap.
type cappedReader struct {
	reader    io.Reader
	remaining int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	// A zero-length read is a no-op regardless of the budget, so its
	// behavior cannot differ on either side of the boundary.
	if len(p) == 0 {
		return 0, nil
	}

	if c.remaining <= 0 {
		// Preserve the io.Reader contract at the boundary: the cap error is
		// reserved for actual excess data -- a legal (0, nil) from the
		// underlying reader passes through for the caller to retry.
		var probe [1]byte
		n, err := c.reader.Read(probe[:])
		if n > 0 {
			return 0, errCertArchiveTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}

	n, err := c.reader.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// archiveCertPair is one certificate directory from an archive, parsed and
// validated.
type archiveCertPair struct {
	certPEM []byte
	keyPEM  []byte
	leaf    *x509.Certificate
}

// certArchiveWarningKind classifies a reader warning, so callers can act on a
// class of warning without being coupled to its human-readable text.
type certArchiveWarningKind int

const (
	// warnMissingCertificate: the state references a certificate whose files
	// the archive does not hold; its domains re-order after a restore.
	warnMissingCertificate certArchiveWarningKind = iota
	// warnAccountKey: the account key entry is unusable and will not restore.
	warnAccountKey
)

type certArchiveWarning struct {
	kind certArchiveWarningKind
	text string
}

// certStoreArchive is a fully read and validated certificate store archive.
// Reading never touches the store: verification and restore share this.
type certStoreArchive struct {
	state    managerState
	hasState bool

	accountKey     []byte
	dynamicDomains []byte

	// extraAccountKeys holds the per-directory account files (--tls-staging
	// identities), keyed by filename.
	extraAccountKeys map[string][]byte

	// certs is keyed by the certificate's directory name (the sanitized
	// certificate identifier).
	certs map[string]archiveCertPair

	warnings []certArchiveWarning
}

// warningTexts flattens the warnings for reporting.
func (a *certStoreArchive) warningTexts() []string {
	if len(a.warnings) == 0 {
		return nil
	}

	texts := make([]string, 0, len(a.warnings))
	for _, warning := range a.warnings {
		texts = append(texts, warning.text)
	}
	return texts
}

// readCertStoreArchive reads and validates an exported certificate store
// archive. Structural problems -- traversal-shaped or unexpected entry names,
// torn certificate pairs, an unparseable or inconsistent state file -- are
// errors: a backup that fails here cannot be trusted to restore. An expired
// certificate is not an error; a faithful backup of an expired certificate is
// still a backup.
func readCertStoreArchive(archivePath string) (certStoreArchive, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return certStoreArchive{}, fmt.Errorf("failed to open the archive: %w", err)
	}
	defer file.Close()

	return readCertStoreArchiveFrom(file, archivePath)
}

// readCertStoreArchiveFrom is readCertStoreArchive over an already-open
// source; archivePath only labels error messages. The exporter uses it to
// verify its staged archive through the file handle it wrote, rather than
// re-opening a path.
func readCertStoreArchiveFrom(source io.Reader, archivePath string) (certStoreArchive, error) {
	archive := certStoreArchive{certs: map[string]archiveCertPair{}}

	gz, err := gzip.NewReader(source)
	if err != nil {
		return archive, fmt.Errorf("failed to read the archive %s: %w", archivePath, err)
	}
	defer gz.Close()

	rawCerts := map[string]map[string][]byte{}
	entryCount, fileCount := 0, 0

	// The cap sits around the whole decompressed gzip stream, not just entry
	// payloads: PAX and GNU metadata records are consumed inside Next() and
	// would otherwise be free decompression work for a hostile archive.
	capped := &cappedReader{reader: gz, remaining: maxCertArchiveBytes}

	tr := tar.NewReader(capped)
	var headerBytes int64
	for {
		beforeHeader := capped.remaining
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, errCertArchiveTooLarge) || capped.remaining <= 0 {
				return archive, fmt.Errorf("refusing the archive %s: it decompresses beyond %d bytes", archivePath, int64(maxCertArchiveBytes))
			}
			return archive, fmt.Errorf("failed to read the archive %s: %w", archivePath, err)
		}

		// Everything Next() consumed is header work -- including PAX/GNU
		// metadata records the entry counter below never sees.
		headerBytes += beforeHeader - capped.remaining
		if headerBytes > maxCertArchiveHeaderBytes {
			return archive, fmt.Errorf("refusing the archive %s: more than %d bytes of tar headers", archivePath, int64(maxCertArchiveHeaderBytes))
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
		fileCount++

		data, err := io.ReadAll(tr)
		if err != nil {
			if errors.Is(err, errCertArchiveTooLarge) {
				return archive, fmt.Errorf("refusing the archive %s: it decompresses beyond %d bytes", archivePath, int64(maxCertArchiveBytes))
			}
			return archive, fmt.Errorf("failed to read the archive entry %q: %w", header.Name, err)
		}

		if err := archive.placeEntry(header.Name, data, rawCerts); err != nil {
			return archive, err
		}
	}

	// Drain the rest of the stream: the tar reader stops at its end-of-archive
	// marker, but the gzip trailer -- its checksum included -- still has to
	// parse and fit the cap, otherwise a corrupt or oversized backup could
	// verify successfully.
	if _, err := io.Copy(io.Discard, capped); err != nil {
		if errors.Is(err, errCertArchiveTooLarge) {
			return archive, fmt.Errorf("refusing the archive %s: it decompresses beyond %d bytes", archivePath, int64(maxCertArchiveBytes))
		}
		return archive, fmt.Errorf("failed to read the archive %s: %w", archivePath, err)
	}

	// Directory headers alone do not make an archive: emptiness is decided by
	// regular files, while the entry cap above counts every header.
	if fileCount == 0 {
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
		if isExtraAccountKeyFile(rest) {
			if a.extraAccountKeys == nil {
				a.extraAccountKeys = map[string][]byte{}
			}
			a.extraAccountKeys[rest] = data
			return nil
		}

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
	a.checkAccountKeys()

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
			a.warnings = append(a.warnings, certArchiveWarning{
				kind: warnMissingCertificate,
				text: fmt.Sprintf("certificate %s is referenced by the state file but missing from the archive; its domains will re-order after a restore", id),
			})
			continue
		}

		// The certificate must actually be what the state record says it is:
		// restoring a record whose leaf names disagree -- in either direction
		// -- would have the manager serving the wrong certificate, and every
		// writer of state records copies the leaf's DNS names exactly, so the
		// sets must match, not merely overlap.
		if !slices.Equal(sortedCopy(record.Domains), sortedCopy(pair.leaf.DNSNames)) {
			return fmt.Errorf("the archived certificate %s names %v, but its state record claims %v",
				id, pair.leaf.DNSNames, record.Domains)
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

// checkAccountKeys drops account key entries that do not hold usable key
// material, with a warning: restoring one would make the next boot silently
// register a fresh ACME account while the operator believes the identity was
// preserved. The estate's certificates still restore.
func (a *certStoreArchive) checkAccountKeys() {
	if a.accountKey != nil && !a.usableAccountKey(a.accountKey, "ACME account key") {
		a.accountKey = nil
	}

	for _, name := range slices.Sorted(maps.Keys(a.extraAccountKeys)) {
		if !a.usableAccountKey(a.extraAccountKeys[name], "ACME account key "+name) {
			delete(a.extraAccountKeys, name)
		}
	}
}

// usableAccountKey reports whether data parses as an account holding an ECDSA
// private key, warning under the given label otherwise. It mirrors
// loadOrCreateUser exactly: that only accepts an ECDSA key, so any other key
// type would be silently discarded at boot and a fresh account registered --
// the very outcome this check exists to make loud.
func (a *certStoreArchive) usableAccountKey(data []byte, label string) bool {
	var user acmeUser
	if err := json.Unmarshal(data, &user); err != nil {
		a.warnings = append(a.warnings, certArchiveWarning{
			kind: warnAccountKey,
			text: fmt.Sprintf("the archived %s does not parse and will not be restored; the next boot will register a fresh account: %v", label, err),
		})
		return false
	}

	key, err := certcrypto.ParsePEMPrivateKey(user.KeyPEM)
	if err == nil {
		if _, ok := key.(*ecdsa.PrivateKey); ok {
			return true
		}
		err = errors.New("the key is not an ECDSA key")
	}

	a.warnings = append(a.warnings, certArchiveWarning{
		kind: warnAccountKey,
		text: fmt.Sprintf("the archived %s holds no usable private key and will not be restored; the next boot will register a fresh account: %v", label, err),
	})
	return false
}

// validateManagerState checks the invariants a healthy manager always
// maintains: both maps present; no null certificate records; identifiers that
// are safe as directory names, unique after sanitization, and consistent with
// their map key; and every domain mapped to a certificate that exists and
// actually covers it. Shared by the Traefik importer (before merging into an
// existing state file) and the archive reader.
func validateManagerState(state managerState) error {
	if state.Certificates == nil || state.DomainMap == nil {
		return errors.New("it does not look like a certificate state file")
	}

	dirs := map[string]string{}
	for id, cert := range state.Certificates {
		if cert == nil {
			return fmt.Errorf("certificate %q is null", id)
		}
		if cert.Identifier != id {
			return fmt.Errorf("certificate %q carries the mismatched identifier %q", id, cert.Identifier)
		}

		// The sanitized identifier becomes an on-disk directory under the
		// certificate path: path-special names would escape it, and two
		// identifiers sharing one sanitized form would overwrite (or delete)
		// each other's files.
		dir := sanitizeFilename(id)
		if dir == "" || dir == "." || dir == ".." {
			return fmt.Errorf("certificate %q does not name a safe storage directory", id)
		}
		if earlier, ok := dirs[dir]; ok {
			return fmt.Errorf("certificates %q and %q collide on the storage directory %q", earlier, id, dir)
		}
		dirs[dir] = id
	}

	for domain, id := range state.DomainMap {
		cert, ok := state.Certificates[id]
		if !ok {
			return fmt.Errorf("domain %q references a missing certificate %q", domain, id)
		}
		if !identifiersCover(cert.Domains, domain) {
			return fmt.Errorf("domain %q is mapped to certificate %q, which does not cover it", domain, id)
		}
	}

	return nil
}
