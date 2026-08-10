package server

import (
	"log/slog"
	"slices"
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
	onChange   func()
}

func (g issuanceGuard) notifyChange() {
	if g.onChange != nil {
		g.onChange()
	}
}

// SetIssuanceGuard installs the preflight probe, quarantine, and persistence
// callback that guard handshake-driven batches. NewDynamicDomainManager
// installs it at boot; without it, provisioning batches behave as before.
func (m *SANCertManager) SetIssuanceGuard(preflight func(domain string) error, quarantine *domainQuarantine, onChange func()) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.guard = issuanceGuard{preflight: preflight, quarantine: quarantine, onChange: onChange}
}

func (m *SANCertManager) issuanceGuardSnapshot() issuanceGuard {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.guard
}

// filterBatchMates drops quarantined or unreachable domains from a handshake
// batch, quarantining fresh probe failures. Every mate is probed, even one
// that held a certificate before — an expiring host whose DNS moved away must
// not ride into the order on its history. The triggering domain is never
// dropped: its handshake is why we are here, and if it is the problem, the
// order failure will be attributed to it. Callers must NOT hold m.mu — the
// probes do network I/O.
func (m *SANCertManager) filterBatchMates(trigger string, domains []string) []string {
	guard := m.issuanceGuardSnapshot()
	if guard.quarantine == nil {
		return domains
	}

	mates := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain == trigger {
			continue
		}
		if guard.quarantine.IsQuarantined(domain) {
			slog.Debug("Leaving quarantined domain out of handshake batch", "domain", domain)
			continue
		}
		mates = append(mates, domain)
	}

	unreachable, failures := probeDomains(mates, guard.preflight)
	for _, domain := range unreachable {
		backoff := guard.quarantine.RecordFailure(domain, quarantinePreflight)
		slog.Warn("Batch domain failed pre-flight probe; holding back",
			"domain", domain, "backoff", backoff, "error", failures[domain])
	}
	if len(unreachable) > 0 {
		guard.notifyChange()
	}

	kept := []string{trigger}
	for _, domain := range mates {
		if !slices.Contains(unreachable, domain) {
			kept = append(kept, domain)
		}
	}
	return kept
}

// clearBatchQuarantine wipes the failure history of a successfully issued
// batch, exactly as the dynamic issuer does — otherwise a domain's next
// failure would start higher up the backoff ladder than it deserves.
func (m *SANCertManager) clearBatchQuarantine(domains []string) {
	guard := m.issuanceGuardSnapshot()
	if guard.quarantine == nil {
		return
	}

	for _, domain := range domains {
		guard.quarantine.Clear(domain)
	}
	guard.notifyChange()
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
	if len(culprits) == 0 {
		culprits, _ = probeDomains(ordered, guard.preflight)
	}
	if len(culprits) == 0 {
		return requested
	}

	// The order may contain planned identifiers (a wildcard collapsed from
	// siblings); blame the requested hosts a culprit identifier covers.
	survivors := []string{}
	quarantined := false
	for _, domain := range requested {
		if identifiersCover(culprits, domain) {
			backoff := guard.quarantine.RecordFailure(domain, quarantineACME)
			slog.Warn("Quarantining culprit of failed handshake batch",
				"domain", domain, "backoff", backoff)
			quarantined = true
			continue
		}
		survivors = append(survivors, domain)
	}
	if quarantined {
		guard.notifyChange()
	}
	return survivors
}
