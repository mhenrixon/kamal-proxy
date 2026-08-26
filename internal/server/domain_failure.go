package server

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme"
)

// Attribution of failed ACME orders to the domains that caused them, shared by
// the dynamic issuer, the background renewer, and the handshake batch guard.

// maxConcurrentProbes bounds parallel pre-flight probes. Each probe can take
// up to preflightTimeout, so a serial sweep over a large batch would block an
// issuance slot (or a waiting handshake) for minutes; concurrency keeps the
// worst case to a few probe timeouts.
const maxConcurrentProbes = 16

// identifyFailedDomains names the domains responsible for a failed order:
// lego's per-domain error lines when present, a pre-flight probe of each
// member otherwise, and the whole set when neither can tell — an
// unattributable failure holds the entire batch on the quarantine ladder so
// retries back off instead of looping against ACME rate limits.
func identifyFailedDomains(err error, domains []string, preflight func(string) error, unprobeable func(string) bool) []string {
	if failed := failedDomainsFromError(err, domains); len(failed) > 0 {
		return failed
	}

	if failed, _ := probeDomains(domains, preflight, unprobeable); len(failed) > 0 {
		return failed
	}

	return domains
}

// probeDomains runs the pre-flight probe over a set of domains with bounded
// concurrency and returns the ones that failed, in input order, with each
// failure's error. A nil probe reports nothing.
//
// Domains the probe cannot speak for are skipped rather than failed: a
// wildcard, which has no name to answer on, and anything unprobeable reports
// — in practice a zone with a DNS-01 provider, whose order never depends on
// where the domain points. Probing those and holding them back on failure
// would punish exactly the case DNS-01 exists to make safe: issuing a
// certificate before a DNS cutover.
func probeDomains(domains []string, preflight func(string) error, unprobeable func(string) bool) ([]string, map[string]error) {
	if preflight == nil {
		return nil, nil
	}

	errs := make([]error, len(domains))
	sem := make(chan struct{}, maxConcurrentProbes)
	var wg sync.WaitGroup
	for idx, domain := range domains {
		if strings.HasPrefix(domain, "*.") || (unprobeable != nil && unprobeable(domain)) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			errs[idx] = preflight(domain)
		}(idx, domain)
	}
	wg.Wait()

	failed := []string{}
	failures := map[string]error{}
	for idx, domain := range domains {
		if errs[idx] != nil {
			failed = append(failed, domain)
			failures[domain] = errs[idx]
		}
	}
	return failed, failures
}

// acmeRateLimitedProblem is the RFC 8555 problem type an ACME server returns
// when a request exceeds a rate limit. lego's own namespace constant is
// unexported, so it is spelled out here.
const acmeRateLimitedProblem = "urn:ietf:params:acme:error:rateLimited"

// rateLimitHoldMargin pads an advertised retry time so the first retry after
// release cannot race the tail of the limit window.
const rateLimitHoldMargin = time.Minute

// acmeRateLimit is a parsed urn:ietf:params:acme:error:rateLimited rejection.
type acmeRateLimit struct {
	identifiers []string  // names the server attributes the limit to
	retryAfter  time.Time // zero when none was advertised or parseable
}

var (
	// Boulder's per-identifier limit messages quote the throttled name, e.g.
	// `too many failed authorizations (5) for "example.com"`.
	quotedNamePattern = regexp.MustCompile(`"([^"]+)"`)

	// Boulder embeds the earliest permitted retry in the detail text ("retry
	// after 2026-08-21 06:00:00 UTC" or an RFC3339 stamp); lego does not carry
	// the Retry-After header onto the error, so the text is the only source.
	retryAfterPattern = regexp.MustCompile(
		`retry after ([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2}| [A-Z]{1,5})?)`)
)

var retryAfterLayouts = []string{
	"2006-01-02 15:04:05 MST",
	time.RFC3339,
	"2006-01-02 15:04:05",
}

// parseRateLimited recognizes an ACME rateLimited rejection anywhere in an
// error chain and extracts the identifiers it names — subproblem identifiers
// plus quoted hostnames in the detail text — and the advertised retry time.
func parseRateLimited(err error) (acmeRateLimit, bool) {
	var details *acme.ProblemDetails
	if !errors.As(err, &details) || details.Type != acmeRateLimitedProblem {
		return acmeRateLimit{}, false
	}

	limit := acmeRateLimit{}
	seen := map[string]struct{}{}
	add := func(name string) {
		if !plausibleHostname(name) {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		limit.identifiers = append(limit.identifiers, name)
	}

	for _, sub := range details.SubProblems {
		add(sub.Identifier.Value)
	}
	for _, match := range quotedNamePattern.FindAllStringSubmatch(details.Detail, -1) {
		add(match[1])
	}

	if match := retryAfterPattern.FindStringSubmatch(details.Detail); match != nil {
		for _, layout := range retryAfterLayouts {
			if parsed, err := time.Parse(layout, match[1]); err == nil {
				limit.retryAfter = parsed
				break
			}
		}
	}

	return limit, true
}

// plausibleHostname filters quoted strings that cannot be order identifiers —
// URLs, prose — before they are blamed for a rate limit.
func plausibleHostname(name string) bool {
	if name == "" || strings.ContainsAny(name, " /:") {
		return false
	}
	return strings.Contains(name, ".")
}

// rateLimitedDomains maps a rate-limit rejection's identifiers onto the
// members of the attempted order: an exact member, or the wildcard member
// whose authorization the identifier names. Only when nothing matched, every
// member under the identifier as a registered domain is blamed instead —
// limits like "too many certificates already issued" throttle the whole
// registration, not one hostname.
func rateLimitedDomains(limit acmeRateLimit, domains []string) []string {
	failed := []string{}
	for _, domain := range domains {
		for _, identifier := range limit.identifiers {
			if domain == identifier || domain == "*."+identifier {
				failed = append(failed, domain)
				break
			}
		}
	}
	if len(failed) > 0 {
		return failed
	}

	for _, domain := range domains {
		for _, identifier := range limit.identifiers {
			if strings.HasSuffix(domain, "."+identifier) {
				failed = append(failed, domain)
				break
			}
		}
	}
	return failed
}

// failedDomainsFromError matches lego's per-domain error lines
// ("<domain>: <cause>") against the attempted domains.
func failedDomainsFromError(err error, domains []string) []string {
	lines := strings.Split(err.Error(), "\n")

	failed := []string{}
	for _, domain := range domains {
		prefix := domain + ": "
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				failed = append(failed, domain)
				break
			}
		}
	}
	return failed
}
