package server

import (
	"log/slog"
)

// Guarding of the handshake-driven provisioning batch.
//
// provisionCertificate batches every pending deploy-registered host into the
// triggering handshake's order. Without a guard, one host whose DNS points
// elsewhere — a typo'd `deploy --host`, a domain surrendered after deploy —
// fails the whole order and starves its batch-mates of certificates forever.
// The guard reuses the dynamic subsystem's preflight probe and quarantine:
// batch-mates that are quarantined or unreachable stay out of the order, and
// a failed order quarantines its identified culprits only.

// issuanceGuard carries the hooks installed by the dynamic domain manager.
type issuanceGuard struct {
	preflight  func(domain string) error
	quarantine *domainQuarantine
}

// SetIssuanceGuard installs the preflight probe and quarantine that guard
// handshake-driven batches. NewDynamicDomainManager installs it at boot;
// without it, provisioning batches behave as before.
func (m *SANCertManager) SetIssuanceGuard(preflight func(domain string) error, quarantine *domainQuarantine) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.guard = issuanceGuard{preflight: preflight, quarantine: quarantine}
}

func (m *SANCertManager) issuanceGuardSnapshot() issuanceGuard {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.guard
}

// filterBatchMates drops quarantined or unreachable domains from a handshake
// batch, quarantining fresh probe failures. The triggering domain is never
// dropped: its handshake is why we are here, and if it is the problem, the
// order failure will be attributed to it. Callers must NOT hold m.mu — the
// probe does network I/O.
func (m *SANCertManager) filterBatchMates(trigger string, domains []string) []string {
	guard := m.issuanceGuardSnapshot()
	if guard.quarantine == nil {
		return domains
	}

	kept := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain == trigger {
			kept = append(kept, domain)
			continue
		}
		if guard.quarantine.IsQuarantined(domain) {
			slog.Debug("Leaving quarantined domain out of handshake batch", "domain", domain)
			continue
		}
		if guard.preflight != nil && !m.HasCertificate(domain) {
			if err := guard.preflight(domain); err != nil {
				backoff := guard.quarantine.RecordFailure(domain, quarantinePreflight)
				slog.Warn("Batch domain failed pre-flight probe; holding back",
					"domain", domain, "backoff", backoff, "error", err)
				continue
			}
		}
		kept = append(kept, domain)
	}
	return kept
}

// attributeBatchFailure quarantines the culprits of a failed handshake order
// and returns the requested domains that should go back to pending. Only a
// culprit narrower than the whole order is quarantined: a generic ACME outage
// must not push deploy-registered hosts onto the quarantine ladder, so an
// unattributable failure restores everything, exactly as an unguarded batch
// would.
func (m *SANCertManager) attributeBatchFailure(err error, ordered, requested []string) []string {
	guard := m.issuanceGuardSnapshot()
	if guard.quarantine == nil {
		return requested
	}

	culprits := failedDomainsFromError(err, ordered)
	if len(culprits) == 0 && guard.preflight != nil {
		for _, identifier := range ordered {
			if identifier[0] == '*' {
				continue
			}
			if probeErr := guard.preflight(identifier); probeErr != nil {
				culprits = append(culprits, identifier)
			}
		}
	}
	if len(culprits) == 0 {
		return requested
	}

	// The order may contain planned identifiers (a wildcard collapsed from
	// siblings); blame the requested hosts a culprit identifier covers.
	survivors := []string{}
	for _, domain := range requested {
		if identifiersCover(culprits, domain) {
			backoff := guard.quarantine.RecordFailure(domain, quarantineACME)
			slog.Warn("Quarantining culprit of failed handshake batch",
				"domain", domain, "backoff", backoff)
			continue
		}
		survivors = append(survivors, domain)
	}
	return survivors
}
