package server

import (
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Attribution of failed ACME orders to the domains that caused them, shared by
// the dynamic issuer and the background renewer.

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
func identifyFailedDomains(err error, domains []string, preflight func(string) error) []string {
	if failed := rateLimitedDomains(err, domains); len(failed) > 0 {
		return failed
	}

	if failed := failedDomainsFromError(err, domains); len(failed) > 0 {
		return failed
	}

	if failed, _ := probeDomains(domains, preflight); len(failed) > 0 {
		return failed
	}

	return domains
}

// rateLimitedIdentifierPattern matches the quoted identifiers a CA's
// rateLimited error names, e.g. Let's Encrypt's `too many failed
// authorizations (5) for "example.com" in the last 1h0m0s`.
var rateLimitedIdentifierPattern = regexp.MustCompile(`"([^"]+)"`)

// rateLimitedDomains attributes a rateLimited order rejection to the batch
// members the error names. The CA throttles per identifier, so one throttled
// domain must not condemn the whole batch: quarantining just the named ones
// lets the survivors re-order immediately instead of waiting out a backoff
// they never earned. An account- or order-scoped limit names no batch member,
// and falls through to the caller's whole-batch handling.
func rateLimitedDomains(err error, domains []string) []string {
	if err == nil || !strings.Contains(err.Error(), "urn:ietf:params:acme:error:rateLimited") {
		return nil
	}

	var failed []string
	for _, match := range rateLimitedIdentifierPattern.FindAllStringSubmatch(err.Error(), -1) {
		name := match[1]
		if slices.Contains(domains, name) && !slices.Contains(failed, name) {
			failed = append(failed, name)
		}
	}
	return failed
}

// probeDomains runs the pre-flight probe over a set of domains with bounded
// concurrency and returns the ones that failed, in input order, with each
// failure's error. Wildcards are skipped — there is no name to answer on one.
// A nil probe reports nothing.
func probeDomains(domains []string, preflight func(string) error) ([]string, map[string]error) {
	if preflight == nil {
		return nil, nil
	}

	errs := make([]error, len(domains))
	sem := make(chan struct{}, maxConcurrentProbes)
	var wg sync.WaitGroup
	for idx, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
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
