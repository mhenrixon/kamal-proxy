package server

import (
	"context"
	"crypto/x509"
	"hash/fnv"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

const (
	// DefaultRenewalCheckInterval is how often managed certificates are
	// checked for renewal.
	DefaultRenewalCheckInterval = time.Hour

	// renewalJitterMax spreads fallback renewals so a fleet of proxies does
	// not renew in lockstep.
	renewalJitterMax = 6 * time.Hour

	// fallbackCertLifetime is assumed when a certificate's leaf (and so its
	// NotBefore) is unavailable.
	fallbackCertLifetime = 90 * 24 * time.Hour
)

// renewalInfoGetter is implemented by obtainers that support ACME Renewal
// Information (RFC 9773).
type renewalInfoGetter interface {
	GetRenewalInfo(request certificate.RenewalInfoRequest) (*certificate.RenewalInfoResponse, error)
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
		config.CheckInterval = DefaultRenewalCheckInterval
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

		if r.shouldRenew(cert) {
			r.renew(cert)
		}
	}

	r.reportMetrics()
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
	domains := r.effectiveDomains(cert)

	if len(domains) == 0 {
		slog.Info("Dropping certificate with no remaining domains", "certificate", cert.Identifier)
		r.manager.removeCertificate(cert.Identifier)
		r.notifyChange()
		return
	}

	domains = r.topUpBatch(domains)
	slices.Sort(domains)

	replaces := ""
	if leaf := certLeaf(cert); leaf != nil {
		if ariCertID, err := certificate.MakeARICertID(leaf); err == nil {
			replaces = ariCertID
		}
	}

	if r.config.Bucket != nil {
		if err := r.config.Bucket.Take(r.ctx); err != nil {
			return
		}
	}

	slog.Info("Renewing certificate", "certificate", cert.Identifier, "domains", domains)

	resource, err := r.config.Obtainer.Obtain(certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		ReplacesCertID: replaces,
	})
	if err != nil {
		r.handleRenewalFailure(cert, domains, err)
		return
	}

	renewed, err := r.manager.adoptCertificate(resource, domains)
	if err != nil {
		slog.Error("Failed to adopt renewed certificate", "certificate", cert.Identifier, "error", err)
		return
	}

	if renewed.Identifier != cert.Identifier {
		r.manager.removeCertificate(cert.Identifier)
	}

	for _, domain := range domains {
		r.quarantine.Clear(domain)
		metrics.Tracker.IncCertificateRenewals(domain, true)
	}

	r.notifyChange()
}

// effectiveDomains filters a certificate's set down to domains that are still
// allowed (deploy-registered or dynamic) and not quarantined.
func (r *certRenewer) effectiveDomains(cert *ManagedCert) []string {
	domains := []string{}
	for _, domain := range cert.Domains {
		if r.manager.DomainAllowed(domain) && !r.quarantine.IsQuarantined(domain) {
			domains = append(domains, domain)
		}
	}
	return domains
}

// topUpBatch fills an under-filled dynamic batch from the pending queue. It
// only applies to certificates owned by a service with a batch size above one.
func (r *certRenewer) topUpBatch(domains []string) []string {
	if r.config.BatchSize == nil || r.config.TakePending == nil {
		return domains
	}

	service, ok := r.dynamicServiceFor(domains)
	if !ok {
		return domains
	}

	size := r.config.BatchSize(service)
	if size <= 1 || len(domains) >= size {
		return domains
	}

	return append(domains, r.config.TakePending(service, size-len(domains))...)
}

func (r *certRenewer) dynamicServiceFor(domains []string) (string, bool) {
	for _, domain := range domains {
		if service, ok := r.manager.dynamicOwner(domain); ok {
			return service, ok
		}
	}
	return "", false
}

func (r *certRenewer) handleRenewalFailure(cert *ManagedCert, domains []string, err error) {
	failed := failedDomainsFromError(err, domains)

	slog.Warn("Certificate renewal failed", "certificate", cert.Identifier,
		"domains", domains, "failed", failed, "error", err)

	for _, domain := range failed {
		r.quarantine.RecordFailure(domain, quarantineACME)
	}
	for _, domain := range domains {
		metrics.Tracker.IncCertificateRenewals(domain, false)
	}

	r.notifyChange()
}

func (r *certRenewer) reportMetrics() {
	certs := r.manager.ManagedCertificates()
	metrics.Tracker.SetCertificateCount(len(certs), 0, len(certs))

	for _, cert := range certs {
		for _, domain := range cert.Domains {
			metrics.Tracker.SetCertificateExpiry(domain, false, cert.NotAfter)
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
