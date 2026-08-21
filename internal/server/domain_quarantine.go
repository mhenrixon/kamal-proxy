package server

import (
	"sync"
	"time"
)

type quarantineKind int

const (
	// quarantineACME marks a failure reported by the ACME server; it starts at
	// a steep backoff because retries burn Let's Encrypt rate limits (5 auth
	// failures per identifier per hour).
	quarantineACME quarantineKind = iota

	// quarantinePreflight marks a failed self-probe: the domain didn't route
	// back to this proxy. No ACME order was spent, so the first retry is soon.
	quarantinePreflight
)

var (
	acmeBackoffLadder      = []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour, 24 * time.Hour}
	preflightBackoffLadder = []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, 4 * time.Hour, 24 * time.Hour}
)

// quarantineEntry records a domain's failure history and current hold.
type quarantineEntry struct {
	Until    time.Time `json:"until"`
	Failures int       `json:"failures"`
}

// domainQuarantine tracks per-domain issuance failures with escalating
// backoff, so one failing domain cannot loop against ACME rate limits.
type domainQuarantine struct {
	mu      sync.Mutex
	entries map[string]*quarantineEntry
	now     func() time.Time
}

func newDomainQuarantine() *domainQuarantine {
	return &domainQuarantine{
		entries: make(map[string]*quarantineEntry),
		now:     time.Now,
	}
}

// RecordFailure escalates a domain's backoff and returns the applied hold.
func (q *domainQuarantine) RecordFailure(domain string, kind quarantineKind) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()

	entry := q.record(domain)

	ladder := acmeBackoffLadder
	if kind == quarantinePreflight {
		ladder = preflightBackoffLadder
	}

	backoff := ladder[min(entry.Failures, len(ladder))-1]
	entry.Until = q.now().Add(backoff)
	return backoff
}

// RecordRateLimited holds a domain until an ACME server's advertised retry
// time plus a safety margin — retrying earlier is a guaranteed failure that
// burns more of the limit — and returns the applied hold. A zero or already
// passed retry time falls back to the ACME ladder. The failure still counts
// toward the ladder history either way.
func (q *domainQuarantine) RecordRateLimited(domain string, retryAfter time.Time) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()

	entry := q.record(domain)

	now := q.now()
	until := retryAfter.Add(rateLimitHoldMargin)
	if retryAfter.IsZero() || !until.After(now) {
		backoff := acmeBackoffLadder[min(entry.Failures, len(acmeBackoffLadder))-1]
		entry.Until = now.Add(backoff)
		return backoff
	}

	entry.Until = until
	return until.Sub(now)
}

// record fetches or creates a domain's entry and counts a failure against it.
// Callers must hold q.mu.
func (q *domainQuarantine) record(domain string) *quarantineEntry {
	entry := q.entries[domain]
	if entry == nil {
		entry = &quarantineEntry{}
		q.entries[domain] = entry
	}
	entry.Failures++
	return entry
}

// Clear removes a domain's failure history (successful issuance, or the
// domain left the source).
func (q *domainQuarantine) Clear(domain string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	delete(q.entries, domain)
}

// IsQuarantined reports whether a domain is currently held back.
func (q *domainQuarantine) IsQuarantined(domain string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	entry := q.entries[domain]
	return entry != nil && q.now().Before(entry.Until)
}

// Filter splits domains into those eligible for issuance and those held back.
func (q *domainQuarantine) Filter(domains []string) (allowed, quarantined []string) {
	for _, domain := range domains {
		if q.IsQuarantined(domain) {
			quarantined = append(quarantined, domain)
		} else {
			allowed = append(allowed, domain)
		}
	}
	return allowed, quarantined
}

// Len returns the number of domains with failure history.
func (q *domainQuarantine) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.entries)
}

// Snapshot copies the quarantine state for persistence.
func (q *domainQuarantine) Snapshot() map[string]quarantineEntry {
	q.mu.Lock()
	defer q.mu.Unlock()

	snapshot := make(map[string]quarantineEntry, len(q.entries))
	for domain, entry := range q.entries {
		snapshot[domain] = *entry
	}
	return snapshot
}

// Restore replaces the quarantine state from a persisted snapshot.
func (q *domainQuarantine) Restore(snapshot map[string]quarantineEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.entries = make(map[string]*quarantineEntry, len(snapshot))
	for domain, entry := range snapshot {
		q.entries[domain] = &quarantineEntry{Until: entry.Until, Failures: entry.Failures}
	}
}
