package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const (
	// basicAuthScheme prefixes every encoded credential, so a future switch to a
	// different hash can be recognized rather than guessed.
	basicAuthScheme = "sha256"

	basicAuthSaltSize   = 16
	basicAuthDigestSize = sha256.Size

	basicAuthRealm = `Basic realm="Restricted", charset="UTF-8"`
)

// basicAuthCredential is a service's stored credential, ready to compare
// against what a request supplies.
//
// Deliberately not an adaptive hash: verification runs on the *unauthenticated*
// request path, so a deliberately slow one would hand an uncacheable
// CPU-exhaustion primitive to exactly the people the password is there to keep
// out. The salt is what defeats precomputation against a leaked state file; it
// does not defend a weak password against an offline dictionary attack.
type basicAuthCredential struct {
	salt   []byte
	digest []byte

	// denyAll marks a credential that could not be read back from saved state.
	// Such a service must refuse every request rather than serve unprotected.
	denyAll bool
}

// EncodeBasicAuthCredential hashes a username and password for storage. The CLI
// calls this, so the plaintext credential never crosses the RPC socket and
// never reaches the state file.
func EncodeBasicAuthCredential(username, password string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("%w: basic auth username cannot be empty", ErrServiceOptionsInvalid)
	}
	if password == "" {
		return "", fmt.Errorf("%w: basic auth password cannot be empty", ErrServiceOptionsInvalid)
	}
	if strings.Contains(username, ":") {
		return "", fmt.Errorf("%w: basic auth username cannot contain a colon", ErrServiceOptionsInvalid)
	}

	salt := make([]byte, basicAuthSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("unable to generate a basic auth salt: %w", err)
	}

	return fmt.Sprintf("%s:%s:%s", basicAuthScheme,
		hex.EncodeToString(salt),
		hex.EncodeToString(basicAuthDigest(salt, username, password)),
	), nil
}

// Private

func basicAuthDigest(salt []byte, username, password string) []byte {
	hash := sha256.New()
	hash.Write(salt)
	hash.Write([]byte(username))
	hash.Write([]byte{':'})
	hash.Write([]byte(password))

	return hash.Sum(nil)
}

func parseBasicAuthCredential(encoded string) (*basicAuthCredential, error) {
	scheme, rest, found := strings.Cut(encoded, ":")
	if !found || scheme != basicAuthScheme {
		return nil, fmt.Errorf("basic auth credential is not a %s value", basicAuthScheme)
	}

	rawSalt, rawDigest, found := strings.Cut(rest, ":")
	if !found {
		return nil, fmt.Errorf("basic auth credential is missing its digest")
	}

	salt, err := hex.DecodeString(rawSalt)
	if err != nil || len(salt) != basicAuthSaltSize {
		return nil, fmt.Errorf("basic auth credential has an unreadable salt")
	}

	digest, err := hex.DecodeString(rawDigest)
	if err != nil || len(digest) != basicAuthDigestSize {
		return nil, fmt.Errorf("basic auth credential has an unreadable digest")
	}

	return &basicAuthCredential{salt: salt, digest: digest}, nil
}

// matches reports whether the supplied credentials are the stored ones. The
// comparison is constant-time, and both sides are fixed-length digests, so
// neither the username nor the password leaks its length.
func (c *basicAuthCredential) matches(username, password string) bool {
	if c == nil || c.denyAll {
		return false
	}

	return subtle.ConstantTimeCompare(basicAuthDigest(c.salt, username, password), c.digest) == 1
}

func (so ServiceOptions) validateBasicAuth() error {
	if so.BasicAuth == "" {
		return nil
	}

	if _, err := parseBasicAuthCredential(so.BasicAuth); err != nil {
		return fmt.Errorf("%w: %s", ErrServiceOptionsInvalid, err)
	}

	return nil
}

// validateBasicAuthHealthCheck rejects the one health check path that would
// quietly unprotect the service. The carve-out below keys off the health check
// path, so pointing it at the root would exempt the service's index page. Note
// that a stripped --path-prefix also resolves to the root, so this covers both.
func validateBasicAuthHealthCheck(options ServiceOptions, targetOptions TargetOptions) error {
	if options.BasicAuth == "" {
		return nil
	}

	path := targetOptions.HealthCheckConfig.Path
	if path == "" || path == rootPath {
		return fmt.Errorf("%w: health-check-path cannot be %q when basic auth is enabled, as that path is served without credentials", ErrServiceOptionsInvalid, rootPath)
	}

	return nil
}

// resolveBasicAuth prepares the stored credential for serving. It never returns
// an error: this runs from initialize, which runs while decoding saved state,
// and failing there would abort the decode of every other service too.
func (s *Service) resolveBasicAuth(options ServiceOptions) *basicAuthCredential {
	if options.BasicAuth == "" {
		return nil
	}

	credential, err := parseBasicAuthCredential(options.BasicAuth)
	if err != nil {
		slog.Error("Unable to read the stored basic auth credential; denying every request to this service", "service", s.name, "error", err)
		return &basicAuthCredential{denyAll: true}
	}

	switch {
	case !options.TLSEnabled:
		slog.Warn("Basic auth is enabled without TLS: credentials will cross the wire in cleartext", "service", s.name)
	case !options.TLSRedirect:
		slog.Warn("Basic auth is enabled with TLS redirection off: plaintext requests will be challenged in the clear", "service", s.name)
	default:
		slog.Info("Basic auth enabled", "service", s.name)
	}

	return credential
}

// rejectUnauthenticated challenges a request that does not carry this service's
// credentials, reporting whether it handled the response.
//
// It is called from serviceRequestWithTarget rather than from a middleware in
// createMiddleware, and the position is load-bearing: the HTTPS redirect lives
// inside that same handler, so every middleware slot runs *before* it. A
// challenge issued from up there would make the browser send the password in
// cleartext before the redirect to https ever fired.
func (s *Service) rejectUnauthenticated(w http.ResponseWriter, r *http.Request) bool {
	if s.basicAuth == nil {
		return false
	}

	// Take the credential off the request before anything can forward or log it,
	// and before the exemptions below return: browsers replay cached credentials
	// to every path in the protection space, including the health check one.
	// HTTP carries a single Authorization header, so a service behind basic auth
	// cannot also pass one through to its target.
	username, password, hasCredentials := r.BasicAuth()
	r.Header.Del("Authorization")

	// The ACME and TLS on-demand probes address the proxy itself, and downstream
	// load balancers must be able to see this service drain during a deploy.
	if isInternalRequest(r) || s.targetOptions.IsHealthCheckRequest(r) {
		return false
	}

	if hasCredentials && s.basicAuth.matches(username, password) {
		return false
	}

	w.Header().Set("WWW-Authenticate", basicAuthRealm)
	SetErrorResponse(w, r, http.StatusUnauthorized, nil)

	return true
}
