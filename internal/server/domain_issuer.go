package server

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

const (
	// DefaultIssuanceBurst and DefaultIssuanceRefillInterval bound ACME order
	// creation to ~250 orders per 3 hours, a safety margin under Let's
	// Encrypt's 300-orders-per-3h account limit.
	DefaultIssuanceBurst          = 20
	DefaultIssuanceRefillInterval = 40 * time.Second

	// DefaultMaxConcurrentOrders caps in-flight ACME orders.
	DefaultMaxConcurrentOrders = 3
)

// certObtainer abstracts the ACME client's certificate acquisition so the
// issuance planner can be tested without a live directory.
type certObtainer interface {
	Obtain(request certificate.ObtainRequest) (*certificate.Resource, error)
}

// issueRequest is one queued domain awaiting issuance.
type issueRequest struct {
	domain  string
	service string
	retried bool // survivors of a failed batch are re-enqueued at most once
}

type domainIssuerConfig struct {
	Obtainer            certObtainer
	Burst               int
	RefillInterval      time.Duration
	MaxConcurrentOrders int

	// Preflight probes that a domain routes back to this proxy before the
	// first issuance attempt. Nil skips probing.
	Preflight func(domain string) error

	// BatchSize returns the certificate batch size for a service (default 1).
	BatchSize func(service string) int

	// OnChange is notified after issuance activity mutates quarantine or
	// certificate state, so it can be persisted.
	OnChange func()
}

// domainIssuer drains a queue of dynamic domains into ACME orders, honoring a
// token-bucket rate limit and a concurrency cap. One failing domain
// quarantines alone; batch survivors are retried exactly once.
type domainIssuer struct {
	manager    *SANCertManager
	quarantine *domainQuarantine
	config     domainIssuerConfig
	bucket     *tokenBucket

	mu       sync.Mutex
	queue    []*issueRequest
	queued   map[string]struct{}
	inflight map[string]struct{}

	wake   chan struct{}
	sem    chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newDomainIssuer(manager *SANCertManager, quarantine *domainQuarantine, config domainIssuerConfig) *domainIssuer {
	if config.Burst == 0 {
		config.Burst = DefaultIssuanceBurst
	}
	if config.RefillInterval == 0 {
		config.RefillInterval = DefaultIssuanceRefillInterval
	}
	if config.MaxConcurrentOrders == 0 {
		config.MaxConcurrentOrders = DefaultMaxConcurrentOrders
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &domainIssuer{
		manager:    manager,
		quarantine: quarantine,
		config:     config,
		bucket:     newTokenBucket(config.Burst, config.RefillInterval),
		queue:      []*issueRequest{},
		queued:     make(map[string]struct{}),
		inflight:   make(map[string]struct{}),
		wake:       make(chan struct{}, 1),
		sem:        make(chan struct{}, config.MaxConcurrentOrders),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start launches the issuance worker.
func (i *domainIssuer) Start() {
	i.wg.Add(1)
	go i.run()
}

// Stop cancels the worker and waits for in-flight orders to finish.
func (i *domainIssuer) Stop() {
	i.cancel()
	i.wg.Wait()
}

// Request enqueues a domain for issuance. Duplicates and quarantined domains
// are dropped; the poller re-requests eligible domains on every poll.
func (i *domainIssuer) Request(domain, service string) {
	if i.quarantine.IsQuarantined(domain) {
		return
	}

	i.mu.Lock()
	_, alreadyQueued := i.queued[domain]
	_, alreadyInflight := i.inflight[domain]
	if alreadyQueued || alreadyInflight {
		i.mu.Unlock()
		return
	}
	i.queue = append(i.queue, &issueRequest{domain: domain, service: service})
	i.queued[domain] = struct{}{}
	i.mu.Unlock()

	i.notify()
}

// QueueLen returns the number of queued issuance requests.
func (i *domainIssuer) QueueLen() int {
	i.mu.Lock()
	defer i.mu.Unlock()

	return len(i.queue)
}

// takePending removes and returns up to n issuable queued domains for a
// service, marking them in-flight so handshakes and polls cannot race them
// into duplicate orders. The renewer uses it to top up under-filled batches
// at renewal boundaries and MUST call releasePending when its order finishes.
func (i *domainIssuer) takePending(service string, n int) []string {
	i.mu.Lock()
	defer i.mu.Unlock()

	taken := []string{}
	remaining := i.queue[:0]
	for _, request := range i.queue {
		if len(taken) < n && request.service == service && i.issuable(request.domain) {
			taken = append(taken, request.domain)
			delete(i.queued, request.domain)
			i.inflight[request.domain] = struct{}{}
		} else {
			remaining = append(remaining, request)
		}
	}
	i.queue = remaining

	return taken
}

// releasePending drops the in-flight hold on domains handed out by
// takePending. Outcomes (certificate or quarantine) must be recorded first.
func (i *domainIssuer) releasePending(domains []string) {
	i.mu.Lock()
	for _, domain := range domains {
		delete(i.inflight, domain)
	}
	i.mu.Unlock()

	i.notify()
}

// Private

func (i *domainIssuer) run() {
	defer i.wg.Done()

	for {
		select {
		case <-i.ctx.Done():
			return
		case <-i.wake:
		}

		for {
			batch := i.nextBatch()
			if len(batch) == 0 {
				break
			}

			if err := i.bucket.Take(i.ctx); err != nil {
				return
			}

			select {
			case i.sem <- struct{}{}:
			case <-i.ctx.Done():
				return
			}

			i.wg.Add(1)
			go func(batch []*issueRequest) {
				defer i.wg.Done()
				defer func() { <-i.sem }()
				i.issue(batch)
			}(batch)
		}
	}
}

// nextBatch pops the next batch of issuable requests: up to the service's
// batch size, all for the same service. Requests that became ineligible
// (quarantined, evicted, or already covered) are dropped; the poller
// re-requests them when they become eligible again.
func (i *domainIssuer) nextBatch() []*issueRequest {
	i.mu.Lock()
	defer i.mu.Unlock()

	for len(i.queue) > 0 {
		head := i.queue[0]
		i.queue = i.queue[1:]
		delete(i.queued, head.domain)

		if !i.issuable(head.domain) {
			continue
		}

		batch := []*issueRequest{head}
		size := i.batchSizeFor(head.service)

		remaining := i.queue[:0]
		for _, request := range i.queue {
			if len(batch) < size && request.service == head.service && i.issuable(request.domain) {
				batch = append(batch, request)
				delete(i.queued, request.domain)
			} else {
				remaining = append(remaining, request)
			}
		}
		i.queue = remaining

		for _, request := range batch {
			i.inflight[request.domain] = struct{}{}
		}

		return batch
	}

	return nil
}

// issuable must be called with i.mu held.
func (i *domainIssuer) issuable(domain string) bool {
	if _, ok := i.inflight[domain]; ok {
		return false
	}

	return !i.quarantine.IsQuarantined(domain) &&
		!i.manager.HasValidCertificate(domain) &&
		i.manager.DomainAllowed(domain)
}

// finishBatch releases the in-flight hold on a batch's domains. Callers must
// record quarantine or certificate outcomes for the batch BEFORE calling it,
// so re-requested domains cannot slip into a duplicate order.
func (i *domainIssuer) finishBatch(batch []*issueRequest) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, request := range batch {
		delete(i.inflight, request.domain)
	}
}

func (i *domainIssuer) batchSizeFor(service string) int {
	if i.config.BatchSize == nil {
		return 1
	}
	if size := i.config.BatchSize(service); size > 0 {
		return min(size, MaxTLSDomainsBatchSize)
	}
	return 1
}

// issue runs one ACME order for a batch of requests.
func (i *domainIssuer) issue(batch []*issueRequest) {
	domains := make([]string, 0, len(batch))
	requests := make(map[string]*issueRequest, len(batch))

	for _, request := range batch {
		if i.config.Preflight != nil && !i.manager.HasCertificate(request.domain) {
			if err := i.config.Preflight(request.domain); err != nil {
				if i.ctx.Err() != nil {
					// Shutting down: the failure is ours, not the domain's
					continue
				}
				backoff := i.quarantine.RecordFailure(request.domain, quarantinePreflight)
				slog.Warn("Domain failed pre-flight probe; holding back",
					"domain", request.domain, "backoff", backoff, "error", err)
				continue
			}
		}
		domains = append(domains, request.domain)
		requests[request.domain] = request
	}

	if len(domains) == 0 {
		i.finishBatch(batch)
		i.notifyChange()
		return
	}

	slices.Sort(domains)

	resource, err := i.config.Obtainer.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		if i.ctx.Err() != nil {
			// The shutdown broke the order (listeners are closing); do not
			// hold that against the domains.
			slog.Info("Certificate order aborted by shutdown", "domains", domains)
			i.finishBatch(batch)
			return
		}
		i.handleObtainFailure(batch, domains, requests, err)
		i.notifyChange()
		return
	}

	if _, err := i.manager.adoptCertificate(resource, domains); err != nil {
		slog.Error("Failed to adopt issued certificate", "domains", domains, "error", err)
		for _, domain := range domains {
			i.quarantine.RecordFailure(domain, quarantineACME)
		}
		i.finishBatch(batch)
		i.notifyChange()
		return
	}

	for _, domain := range domains {
		i.quarantine.Clear(domain)
	}
	i.finishBatch(batch)

	slog.Info("Dynamic certificate issued", "domains", domains)
	i.notifyChange()
}

// handleObtainFailure quarantines the identifiable culprits and re-enqueues
// the survivors exactly once. Survivors that already had their retry are
// quarantined too, so a failing batch cannot loop against ACME rate limits;
// the poller re-requests them after the backoff expires.
func (i *domainIssuer) handleObtainFailure(batch []*issueRequest, domains []string, requests map[string]*issueRequest, err error) {
	failed := failedDomainsFromError(err, domains)
	if len(failed) == 0 {
		failed = domains
	}

	slog.Warn("Certificate order failed", "domains", domains, "failed", failed, "error", err)

	for _, domain := range failed {
		i.quarantine.RecordFailure(domain, quarantineACME)
	}

	survivors := []*issueRequest{}
	for _, domain := range domains {
		if slices.Contains(failed, domain) {
			continue
		}

		request := requests[domain]
		if request.retried {
			i.quarantine.RecordFailure(domain, quarantineACME)
			continue
		}
		survivors = append(survivors, request)
	}

	// Outcomes are recorded; release the in-flight hold before re-enqueueing
	// so the survivors are not dropped as in-flight at the next dequeue.
	i.finishBatch(batch)

	i.mu.Lock()
	for _, request := range survivors {
		if _, ok := i.queued[request.domain]; !ok {
			i.queue = append(i.queue, &issueRequest{domain: request.domain, service: request.service, retried: true})
			i.queued[request.domain] = struct{}{}
		}
	}
	i.mu.Unlock()

	i.notify()
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

func (i *domainIssuer) notify() {
	select {
	case i.wake <- struct{}{}:
	default:
	}
}

func (i *domainIssuer) notifyChange() {
	if i.config.OnChange != nil {
		i.config.OnChange()
	}
}
