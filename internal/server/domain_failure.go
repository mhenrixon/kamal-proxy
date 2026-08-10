package server

import "strings"

// Attribution of failed ACME orders to the domains that caused them, shared by
// the dynamic issuer and the background renewer.

// identifyFailedDomains names the domains responsible for a failed order:
// lego's per-domain error lines when present, a pre-flight probe of each
// member otherwise, and the whole set when neither can tell — an
// unattributable failure holds the entire batch on the quarantine ladder so
// retries back off instead of looping against ACME rate limits.
func identifyFailedDomains(err error, domains []string, preflight func(string) error) []string {
	if failed := failedDomainsFromError(err, domains); len(failed) > 0 {
		return failed
	}

	if preflight != nil {
		failed := []string{}
		for _, domain := range domains {
			if strings.HasPrefix(domain, "*.") {
				continue
			}
			if probeErr := preflight(domain); probeErr != nil {
				failed = append(failed, domain)
			}
		}
		if len(failed) > 0 {
			return failed
		}
	}

	return domains
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
