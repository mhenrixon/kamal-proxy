package server

import (
	"context"
	"crypto/x509"
	"hash/fnv"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

const (
	// DefaultDynamicRenewalCheckInterval is how often managed certificates are
	// checked for renewal.
	DefaultDynamicRenewalCheckInterval = time.Hour

	// renewalJitterMax spreads fallback renewals so a fleet of proxies does
	// not renew in lockstep.
	renewalJitterMax = 6 * time.Hour

	// fallbackCertLifetime is assumed when a certificate's leaf (and so its
	// NotBefore) is unavailable.
	fallbackCertLifetime = 90 * 24 * time.Hour

	// quarantineCompactionWindow is how close to expiry a partially
	// quarantined certificate is renewed WITHOUT its quarantined members.
	// Further out, renewal is deferred so a transient failure cannot unmap a
	// domain from its still-valid certificate.
	quarantineCompactionWindow = 7 * 24 * time.Hour
)

// renewalInfoGetter is implemented by obtainers that support ACME Renewal
// Information (RFC 9773).
type renewalInfoGetter interface {
	GetRenewalInfo(request certificate.RenewalInfoRequest) (*certificate.RenewalInfoResponse, error)
}

// directoryObtainer is implemented by obtainers that can pin an order to a
// specific ACME directory. The renewer prefers it when available, so a
// partition whose owners are temporarily unresolvable still orders under the
// certificate's recorded identity instead of the resolver's run-level
// fallback.
type directoryObtainer interface {
	ObtainAt(directory string, request certificate.ObtainRequest) (*certificate.Resource, error)
}

type certRenewerConfig struct {
	Obtainer certObtainer

	// Bucket, when set, throttles renewal orders alongside new issuance.
	Bucket *tokenBucket

	// BatchSize returns a service's certificate batch size (default 1).
	BatchSize func(service string) int

	// TakePending supplies queued domains to top up an under-filled batch;
	// membership changes happen ONLY at renewal boundaries.
	TakePending func(service string, n int) []string

	// ReleasePending returns the in-flight hold on topped-up domains once
	// their renewal order has finished.
	ReleasePending func(domains []string)

	// Preflight probes a never-issued top-up domain before it joins a live
	// renewal order. Nil skips probing.
	Preflight func(domain string) error

	// OnChange is notified after renewal activity mutates state.
	OnChange func()

	CheckInterval time.Duration
}

// certRenewer renews managed certificates in the background: inside the ARI
// suggested window when the server provides one, otherwise at two-thirds of
// the certificate's lifetime plus jitter. This works for the 90-day and
// 45-day eras alike — nothing assumes a 30-day margin.
type certRenewer struct {
	manager    *SANCertManager
	quarantine *domainQuarantine
	config     certRenewerConfig

	now    func() time.Time
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newCertRenewer(manager *SANCertManager, quarantine *domainQuarantine, config certRenewerConfig) *certRenewer {
	if config.CheckInterval == 0 {
		config.CheckInterval = DefaultDynamicRenewalCheckInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &certRenewer{
		manager:    manager,
		quarantine: quarantine,
		config:     config,
		now:        time.Now,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start launches the renewal loop.
func (r *certRenewer) Start() {
	r.wg.Add(1)
	go r.run()
}

// Stop cancels the renewal loop and waits for it to finish.
func (r *certRenewer) Stop() {
	r.cancel()
	r.wg.Wait()
}

// Private

func (r *certRenewer) run() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.config.CheckInterval)
	defer ticker.Stop()

	r.reconcile()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.reconcile()
		}
	}
}

// reconcile checks every managed certificate once, renewing or dropping as
// needed, then refreshes the certificate metrics.
func (r *certRenewer) reconcile() {
	for _, cert := range r.manager.ManagedCertificates() {
		if r.ctx.Err() != nil {
			return
		}

		// A certificate with no domain that is both still allowed and still
		// mapped to it has been superseded or fully evicted: retire it
		// instead of renewing it forever.
		if len(r.renewableDomains(cert)) == 0 {
			r.retireCertificate(cert)
			continue
		}

		// The directory check comes first: a switched certificate must be
		// replaced regardless of what ARI (queried at a directory that may no
		// longer be the right one) would say about its timing.
		if r.directoryChanged(cert) || r.shouldRenew(cert) {
			r.renew(cert)
		}
	}

	r.reportMetrics()
}

// directoryChanged reports whether any of the certificate's domains is owned
// by a service that wants a different ACME directory than the one that issued
// it. After a --tls-staging flip the certificate is replaced on the next
// reconcile rather than at the renewal window: a staging certificate is not
// browser-trusted, and a production one spends rate limits the operator opted
// out of. The renewal then splits along directory boundaries, so each
// replacement is ordered under its owner's identity. A certificate with no
// resolvable owner keeps its recorded directory — services may simply not
// have re-attached yet after a restart.
func (r *certRenewer) directoryChanged(cert *ManagedCert) bool {
	return r.manager.certDirectoryMismatched(cert)
}

func (r *certRenewer) shouldRenew(cert *ManagedCert) bool {
	leaf := certLeaf(cert)

	if leaf != nil {
		if ari, ok := r.config.Obtainer.(renewalInfoGetter); ok {
			response, err := ari.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
			if err == nil && response != nil {
				return response.ShouldRenewAt(r.now(), 0) != nil
			}
			slog.Debug("ARI renewal info unavailable, using fallback window",
				"certificate", cert.Identifier, "error", err)
		}
	}

	lifetime := fallbackCertLifetime
	if leaf != nil {
		lifetime = cert.NotAfter.Sub(leaf.NotBefore)
	}

	threshold := cert.NotAfter.Add(-lifetime / 3).Add(certJitter(cert.Identifier))
	return !r.now().Before(threshold)
}

// renew re-obtains a certificate for its identifier set minus evicted and
// quarantined members. An unchanged set keeps Let's Encrypt's renewal
// exemption; ARI `replaces` exempts the order entirely where supported.
func (r *certRenewer) renew(cert *ManagedCert) {
	allowed := r.renewableDomains(cert)
	if len(allowed) == 0 {
		// reconcile retires zero-renewable certificates before calling renew.
		return
	}

	domains, quarantined := r.quarantine.Filter(allowed)
	if len(domains) == 0 {
		slog.Info("Deferring renewal; all remaining domains are quarantined",
			"certificate", cert.Identifier, "quarantined", quarantined)
		return
	}

	// While there is time, wait for quarantined members rather than renewing
	// without them: a shrunken set would unmap them from a still-valid
	// certificate AND forfeit the identical-set renewal exemption. Compact
	// only when expiry is close.
	if len(quarantined) > 0 && time.Until(cert.NotAfter) > quarantineCompactionWindow {
		slog.Info("Deferring renewal until quarantined members recover",
			"certificate", cert.Identifier, "quarantined", quarantined)
		return
	}

	// Probe the remaining members before spending an order: a tenant whose
	// DNS moved away would fail validation and could sink the whole batch —
	// or worse, fail in a way ACME does not attribute to any one domain.
	// Unreachable members follow the same policy as quarantined ones.
	if unreachable := r.preflightMembers(domains); len(unreachable) > 0 {
		if time.Until(cert.NotAfter) > quarantineCompactionWindow {
			slog.Info("Deferring renewal until unreachable members recover",
				"certificate", cert.Identifier, "unreachable", unreachable)
			return
		}

		domains = slices.DeleteFunc(domains, func(domain string) bool {
			return slices.Contains(unreachable, domain)
		})
		if len(domains) == 0 {
			slog.Info("Deferring renewal; every member failed the pre-flight probe",
				"certificate", cert.Identifier)
			return
		}
	}

	domains, toppedUp := r.topUpBatch(domains)
	defer func() {
		if r.config.ReleasePending != nil && len(toppedUp) > 0 {
			r.config.ReleasePending(toppedUp)
		}
	}()
	slices.Sort(domains)

	replaces := ""
	if leaf := certLeaf(cert); leaf != nil {
		if ariCertID, err := certificate.MakeARICertID(leaf); err == nil {
			replaces = ariCertID
		}
	}

	// A certificate issued before zone mappings existed can span DNS
	// providers, and a legacy certificate can span services whose directories
	// have since diverged; its renewal splits along both boundaries, one
	// order per partition. A certificate can only be "replaced" once, and the
	// marker only means something to the CA that issued the predecessor (RFC
	// 9773 tells a CA to reject a replaces identifier it never issued), so
	// the ARI marker rides the first order that stays at the recorded
	// directory — a full directory switch sends no marker at all.
	recorded := r.manager.normalizeDirectory(cert.Directory)
	renewedAll := true
	ariConsumed := false
	newIdentifiers := []string{}
partitionLoop:
	for _, directoryPart := range r.manager.splitByDesiredDirectory(cert, domains) {
		for _, partition := range r.manager.splitByProviderZone(directoryPart.domains) {
			partitionReplaces := ""
			if !ariConsumed && directoryPart.directory == recorded {
				partitionReplaces = replaces
			}

			renewed, adopted, ordered, halt := r.renewPartition(cert, partition, partitionReplaces, directoryPart.directory)
			// The marker is spent once the CA accepted an order carrying it —
			// adoption can still fail locally, but re-sending an identifier
			// the CA already honored would have the next order rejected. An
			// order the CA refused leaves the marker for a later partition.
			if partitionReplaces != "" && ordered {
				ariConsumed = true
			}
			if halt {
				// An account-level rate limit dooms every further order from
				// this account until its advertised retry time; the remaining
				// partitions wait for the next reconcile instead of being
				// submitted into the same limit now.
				renewedAll = false
				break partitionLoop
			}
			if !adopted {
				renewedAll = false
				continue
			}
			newIdentifiers = append(newIdentifiers, renewed.Identifier)
		}
	}

	// The old certificate goes only when every partition has a successor: a
	// failed partition's domains keep serving it until the next reconcile.
	if renewedAll && !slices.Contains(newIdentifiers, cert.Identifier) {
		r.manager.removeCertificate(cert.Identifier)
	}

	if len(newIdentifiers) > 0 {
		r.notifyChange()
	}
}

// renewPartition runs one renewal order at the partition's directory and
// adopts its certificate. adopted reports end-to-end success; ordered reports
// that the CA accepted the order (which spends an ARI replaces marker even if
// adoption then fails locally); halt reports an account-level rate limit that
// dooms the certificate's remaining partitions in this pass. Failures
// quarantine or log exactly as a whole-certificate renewal did.
func (r *certRenewer) renewPartition(cert *ManagedCert, domains []string, replaces, directory string) (renewed *ManagedCert, adopted, ordered, halt bool) {
	if r.config.Bucket != nil {
		if err := r.config.Bucket.Take(r.ctx); err != nil {
			return nil, false, false, false
		}
	}

	slog.Info("Renewing certificate", "certificate", cert.Identifier, "domains", domains, "directory", directory)

	request := certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		ReplacesCertID: replaces,
	}

	var resource *certificate.Resource
	var err error
	if pinned, ok := r.config.Obtainer.(directoryObtainer); ok {
		resource, err = pinned.ObtainAt(directory, request)
	} else {
		resource, err = r.config.Obtainer.Obtain(request)
	}
	if err != nil {
		return nil, false, false, r.handleRenewalFailure(cert, domains, err)
	}

	renewed, err = r.manager.adoptCertificateAt(resource, domains, directory)
	if err != nil {
		slog.Error("Failed to adopt renewed certificate", "certificate", cert.Identifier, "error", err)
		return nil, false, true, false
	}

	for _, domain := range domains {
		r.quarantine.Clear(domain)
		metrics.Tracker.IncCertificateRenewals(domain, true)
	}

	return renewed, true, true, false
}

// retireCertificate disposes of a certificate with no renewable domains. A
// superseded certificate — nothing maps through it anymore — goes immediately.
// An evicted certificate that still serves a mapped domain is kept until its
// own expiry: eviction can be a lying domain source, and deleting the key
// would turn one bad poll into a certificate outage for every member.
func (r *certRenewer) retireCertificate(cert *ManagedCert) {
	if r.certStillServes(cert) && r.now().Before(cert.NotAfter) {
		slog.Debug("Keeping evicted certificate until expiry",
			"certificate", cert.Identifier, "expires", cert.NotAfter)
		return
	}

	slog.Info("Removing certificate with no remaining domains", "certificate", cert.Identifier)
	r.manager.removeCertificate(cert.Identifier)
	r.notifyChange()
}

// certStillServes reports whether any of a certificate's domains still map to
// it — i.e. a handshake for that name would be answered with this certificate.
func (r *certRenewer) certStillServes(cert *ManagedCert) bool {
	for _, domain := range cert.Domains {
		if r.manager.certIDForDomain(domain) == cert.Identifier {
			return true
		}
	}
	return false
}

// renewableDomains filters a certificate's set down to domains that are still
// allowed (deploy-registered or dynamic) AND still mapped to this certificate
// — a domain that moved to a newer certificate no longer renews through this
// one.
func (r *certRenewer) renewableDomains(cert *ManagedCert) []string {
	domains := []string{}
	for _, domain := range cert.Domains {
		if r.manager.DomainAllowed(domain) && r.manager.certIDForDomain(domain) == cert.Identifier {
			domains = append(domains, domain)
		}
	}
	return domains
}

// topUpBatch fills an under-filled dynamic batch from the pending queue,
// pre-flighting never-issued candidates so an unreachable newcomer cannot sink
// a live renewal order. It returns the batch plus the taken domains, which the
// caller must release once the order finishes. It only applies to certificates
// owned by a service with a batch size above one.
func (r *certRenewer) topUpBatch(domains []string) (batch, taken []string) {
	if r.config.BatchSize == nil || r.config.TakePending == nil {
		return domains, nil
	}

	service, ok := r.dynamicServiceFor(domains)
	if !ok {
		return domains, nil
	}

	size := r.config.BatchSize(service)
	if size <= 1 || len(domains) >= size {
		return domains, nil
	}

	kept := []string{}
	for _, domain := range r.config.TakePending(service, size-len(domains)) {
		if r.config.Preflight != nil && !r.manager.HasCertificate(domain) {
			if err := r.config.Preflight(domain); err != nil {
				backoff := r.quarantine.RecordFailure(domain, quarantinePreflight)
				slog.Warn("Top-up domain failed pre-flight probe; holding back",
					"domain", domain, "backoff", backoff, "error", err)
				if r.config.ReleasePending != nil {
					r.config.ReleasePending([]string{domain})
				}
				continue
			}
		}
		kept = append(kept, domain)
	}

	return append(domains, kept...), kept
}

// preflightMembers probes a renewal batch's dynamic members and quarantines
// the unreachable ones. Only dynamic (tenant-supplied) domains are probed:
// they must route back to this proxy to be validated or served at all. A
// deploy-registered host may be reachable over DNS-01 only, and a wildcard
// has no name to answer on, so neither is probed.
func (r *certRenewer) preflightMembers(domains []string) []string {
	if r.config.Preflight == nil {
		return nil
	}

	probeable := []string{}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			continue
		}
		if _, dynamic := r.manager.dynamicOwner(domain); !dynamic {
			continue
		}
		probeable = append(probeable, domain)
	}

	unreachable, failures := probeDomains(probeable, r.config.Preflight)
	for _, domain := range unreachable {
		backoff := r.quarantine.RecordFailure(domain, quarantinePreflight)
		slog.Warn("Renewal member failed pre-flight probe; holding back",
			"domain", domain, "backoff", backoff, "error", failures[domain])
	}
	return unreachable
}

func (r *certRenewer) dynamicServiceFor(domains []string) (string, bool) {
	for _, domain := range domains {
		if service, ok := r.manager.dynamicOwner(domain); ok {
			return service, ok
		}
	}
	return "", false
}

// handleRenewalFailure attributes a failed renewal order and quarantines the
// culprits. It reports halt when the failure was an account-level rate limit:
// every further order from this account is doomed until the advertised retry
// time, so the caller must stop submitting the certificate's remaining
// partitions in this pass.
func (r *certRenewer) handleRenewalFailure(cert *ManagedCert, domains []string, err error) (halt bool) {
	if r.ctx.Err() != nil {
		// The shutdown broke the order; do not hold that against the domains.
		slog.Info("Certificate renewal aborted by shutdown", "certificate", cert.Identifier)
		return false
	}

	// A rate-limited rejection names its own culprits: hold them until the
	// server's advertised retry time — nothing else in the set deserves the
	// ladder, and the next reconcile renews without the held members. Nothing
	// named means an account-level limit; then everyone waits it out.
	if limit, ok := parseRateLimited(err); ok {
		failed := rateLimitedDomains(limit, domains)
		accountLevel := len(failed) == 0
		if accountLevel {
			failed = domains
		}

		slog.Warn("Certificate renewal rate-limited", "certificate", cert.Identifier,
			"domains", domains, "failed", failed, "retryAfter", limit.retryAfter, "error", err)

		for _, domain := range failed {
			r.quarantine.RecordRateLimited(domain, limit.retryAfter)
		}
		for _, domain := range domains {
			metrics.Tracker.IncCertificateRenewals(domain, false)
		}

		r.notifyChange()
		return accountLevel
	}

	// Probe only dynamic members when attributing the failure: a registered
	// host may be DNS-01-only and unreachable over HTTP by design.
	probe := r.config.Preflight
	if probe != nil {
		preflight := probe
		probe = func(domain string) error {
			if _, dynamic := r.manager.dynamicOwner(domain); !dynamic {
				return nil
			}
			return preflight(domain)
		}
	}

	failed := identifyFailedDomains(err, domains, probe)

	slog.Warn("Certificate renewal failed", "certificate", cert.Identifier,
		"domains", domains, "failed", failed, "error", err)

	for _, domain := range failed {
		r.quarantine.RecordFailure(domain, quarantineACME)
	}
	for _, domain := range domains {
		metrics.Tracker.IncCertificateRenewals(domain, false)
	}

	r.notifyChange()
	return false
}

func (r *certRenewer) reportMetrics() {
	certs := r.manager.ManagedCertificates()

	wildcard := 0
	for _, cert := range certs {
		if containsWildcard(cert.Domains) {
			wildcard++
		}
	}

	// The third gauge counts what the wildcards are not. It is labeled http01
	// for continuity with the gauge kamal-proxy has always published, and it is
	// still the honest split for the common case: a wildcard needs DNS-01, and
	// everything else is issued over HTTP-01 unless a DNS provider is
	// configured, in which case the manager does not record which one answered.
	metrics.Tracker.SetCertificateCount(len(certs), wildcard, len(certs)-wildcard)

	for _, cert := range certs {
		isWildcard := containsWildcard(cert.Domains)
		for _, domain := range cert.Domains {
			// Evicted certificates linger until expiry; only the certificate a
			// domain currently maps to may report that domain's expiry, or the
			// zombie would clobber the gauge of its successor.
			if r.manager.certIDForDomain(domain) != cert.Identifier {
				continue
			}
			metrics.Tracker.SetCertificateExpiry(domain, isWildcard, cert.NotAfter)
		}
	}
}

func (r *certRenewer) notifyChange() {
	if r.config.OnChange != nil {
		r.config.OnChange()
	}
}

func certLeaf(cert *ManagedCert) *x509.Certificate {
	if cert.Certificate == nil {
		return nil
	}
	return cert.Certificate.Leaf
}

// certJitter derives a stable per-certificate jitter in [0, renewalJitterMax)
// so renewal times spread without flapping between checks.
func certJitter(certID string) time.Duration {
	h := fnv.New64a()
	h.Write([]byte(certID))
	return time.Duration(h.Sum64() % uint64(renewalJitterMax))
}
