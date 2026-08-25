package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

const (
	// DefaultTLSDomainsInterval is how often a domain source is polled when no
	// interval is configured.
	DefaultTLSDomainsInterval = 5 * time.Minute

	// MinTLSDomainsInterval protects the app from being hammered by polls.
	MinTLSDomainsInterval = 10 * time.Second

	// MaxTLSDomainsBatchSize caps SANs per dynamic certificate. Let's Encrypt's
	// newer profiles (tlsserver/shortlived) allow at most 25 SANs per cert.
	MaxTLSDomainsBatchSize = 25

	// preflightTimeout bounds the pre-issuance self-probe.
	preflightTimeout = 5 * time.Second

	// shrinkGuardThreshold is the fraction of a service's applied domain set
	// that must disappear in a single poll before the removals are held for
	// confirmation instead of applied. One truncated or empty response from
	// the app must not evict the certificate estate.
	shrinkGuardThreshold = 0.30

	// shrinkGuardConfirmations is how many consecutive over-threshold polls
	// it takes before a held mass-removal is trusted and applied.
	shrinkGuardConfirmations = 3
)

// validDomainSource reports whether a tls-domains-source value is usable: a
// path resolved against the service's own targets, or an absolute http(s) URL.
func validDomainSource(source string) bool {
	if strings.HasPrefix(source, "/") {
		return true
	}
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

// DynamicDomainConfig configures the dynamic domain subsystem.
type DynamicDomainConfig struct {
	// StatePath is where the last-known domain sets and quarantine records are
	// persisted, so boot does not depend on the app being up.
	StatePath string

	// RefreshToken authorizes POST /.kamal-proxy/domains/refresh. Empty
	// disables the endpoint.
	RefreshToken string

	// SourceToken, when set, is sent as a bearer token with domain source
	// polls.
	SourceToken string

	// ReleaseProbeInterval is how often held domains are re-probed so a hold
	// can be lifted as soon as the domain routes here again. Zero uses
	// DefaultReleaseProbeInterval; negative disables release probing.
	ReleaseProbeInterval time.Duration
}

// serviceResolver locates a deployed service; implemented by *Router.
type serviceResolver interface {
	serviceForName(name string) *Service
}

// serviceSettings caches the per-service dynamic domain options captured at
// deploy time, so background goroutines never read live ServiceOptions.
type serviceSettings struct {
	source    string
	interval  time.Duration
	batchSize int
	host      string
}

// DynamicDomainManager coordinates the dynamic domain subsystem: per-service
// domain source pollers, the issuance planner, quarantine, the background
// renewer, and state persistence.
type DynamicDomainManager struct {
	config     DynamicDomainConfig
	manager    *SANCertManager
	resolver   serviceResolver
	quarantine *domainQuarantine
	issuer     *domainIssuer
	renewer    *certRenewer
	releaser   *releaseProber

	mu          sync.Mutex
	sources     map[string]*domainSource
	settings    map[string]serviceSettings
	states      map[string]*serviceDomainState
	holds       map[string]*shrinkHold
	lastRefresh time.Time

	preflightNonce string
	probeClient    *http.Client
}

func NewDynamicDomainManager(config DynamicDomainConfig, manager *SANCertManager, resolver serviceResolver) *DynamicDomainManager {
	dm := &DynamicDomainManager{
		config:         config,
		manager:        manager,
		resolver:       resolver,
		quarantine:     newDomainQuarantine(),
		sources:        make(map[string]*domainSource),
		settings:       make(map[string]serviceSettings),
		states:         make(map[string]*serviceDomainState),
		holds:          make(map[string]*shrinkHold),
		preflightNonce: generateNonce(),
		probeClient: &http.Client{
			Timeout: preflightTimeout,
			// Never follow redirects: the probed domain is tenant-supplied,
			// and a redirect could point the proxy at internal targets (SSRF).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	dm.issuer = newDomainIssuer(manager, dm.quarantine, domainIssuerConfig{
		Obtainer:  managerObtainer{manager: manager},
		Preflight: dm.preflightProbe,
		BatchSize: dm.batchSizeFor,
		OnChange:  dm.saveState,
	})

	dm.renewer = newCertRenewer(manager, dm.quarantine, certRenewerConfig{
		Obtainer:       managerObtainer{manager: manager},
		Bucket:         dm.issuer.bucket,
		BatchSize:      dm.batchSizeFor,
		TakePending:    dm.issuer.takePending,
		ReleasePending: dm.issuer.releasePending,
		Preflight:      dm.preflightProbe,
		OnChange:       dm.saveState,
	})

	dm.releaser = newReleaseProber(dm.quarantine, releaseProberConfig{
		Interval:    releaseProbeInterval(config.ReleaseProbeInterval),
		Preflight:   dm.preflightProbe,
		Unprobeable: manager.hasDNSProviderFor,
		Released:    dm.requestIssuanceAfterRelease,
		OnChange:    dm.saveState,
	})

	manager.SetDynamicCertRequester(dm.issuer.Request)
	manager.SetIssuanceGuard(dm.preflightProbe, dm.quarantine, dm.saveState)

	dm.loadState()

	return dm
}

// releaseProbeInterval maps the configured value onto the prober's contract:
// zero means "unset, use the default", negative means the operator turned it
// off, and the prober treats any non-positive interval as disabled.
func releaseProbeInterval(configured time.Duration) time.Duration {
	if configured == 0 {
		return DefaultReleaseProbeInterval
	}
	return configured
}

// requestIssuanceAfterRelease queues a freshly released domain for issuance if
// it still needs a certificate.
//
// Only dynamic domains are queued. A deploy-registered host is issued on its
// handshake, and that path re-probes the trigger itself, so lifting the hold
// is all it needs — routing the two through different mechanisms here would
// risk a background order racing a synchronous one for the same name.
func (dm *DynamicDomainManager) requestIssuanceAfterRelease(domain string) {
	if dm.manager.HasValidCertificate(domain) {
		return
	}
	if service, dynamic := dm.manager.dynamicOwner(domain); dynamic {
		dm.issuer.Request(domain, service)
	}
}

// Start launches the issuance worker, the renewal loop, and the release prober.
func (dm *DynamicDomainManager) Start() {
	dm.issuer.Start()
	dm.renewer.Start()
	dm.releaser.Start()
}

// Stop shuts down pollers, the issuance worker, the renewal loop, and the
// release prober, and persists state.
func (dm *DynamicDomainManager) Stop() {
	dm.mu.Lock()
	sources := make([]*domainSource, 0, len(dm.sources))
	for _, source := range dm.sources {
		sources = append(sources, source)
	}
	dm.mu.Unlock()

	for _, source := range sources {
		source.Stop()
	}

	dm.releaser.Stop()
	dm.renewer.Stop()
	dm.issuer.Stop()
	dm.saveState()
}

// ServiceDeployed reconciles a service's domain source after a deploy. A
// service without a source (or without TLS) has any previous source removed
// and its dynamic domains evicted.
func (dm *DynamicDomainManager) ServiceDeployed(name string, options ServiceOptions) {
	if !options.TLSEnabled || options.TLSDomainsSource == "" {
		dm.ServiceRemoved(name)
		return
	}

	host := ""
	if options.HasConfiguredHosts() {
		host = options.Hosts[0]
	}

	dm.mu.Lock()

	previous := dm.sources[name]
	dm.settings[name] = serviceSettings{
		source:    options.TLSDomainsSource,
		interval:  options.TLSDomainsInterval,
		batchSize: options.TLSDomainsBatchSize,
		host:      host,
	}

	// Confirmations counted against the old source must not carry over to the
	// new one: a redeploy's first shrunken poll starts the count fresh.
	delete(dm.holds, name)

	state := dm.states[name]
	if state == nil {
		state = &serviceDomainState{Domains: []string{}}
		dm.states[name] = state
	}

	source := newDomainSource(domainSourceConfig{
		Service:   name,
		Source:    options.TLSDomainsSource,
		Interval:  options.TLSDomainsInterval,
		Token:     dm.config.SourceToken,
		Endpoint:  dm.endpointFor(name),
		OnDomains: func(domains []string) { dm.applyDomains(name, domains) },
	})
	source.SeedETag(state.ETag)
	dm.sources[name] = source

	persisted := append([]string{}, state.Domains...)
	dm.mu.Unlock()

	if previous != nil {
		previous.Stop()
	}

	// Serve persisted domains immediately; the first poll reconciles.
	dm.manager.SetDynamicDomains(name, persisted)
	for _, domain := range persisted {
		if !dm.manager.HasValidCertificate(domain) {
			dm.issuer.Request(domain, name)
		}
	}

	source.Start()

	slog.Info("Domain source configured", "service", name, "source", options.TLSDomainsSource,
		"persisted_domains", len(persisted))
}

// ServiceRemoved stops a service's poller and evicts its dynamic domains.
func (dm *DynamicDomainManager) ServiceRemoved(name string) {
	dm.mu.Lock()
	source := dm.sources[name]
	state := dm.states[name]
	delete(dm.sources, name)
	delete(dm.settings, name)
	delete(dm.states, name)
	delete(dm.holds, name)
	dm.mu.Unlock()

	if source == nil && state == nil {
		return
	}

	if source != nil {
		source.Stop()
	}

	if state != nil {
		for _, domain := range state.Domains {
			dm.quarantine.Clear(domain)
		}
	}

	dm.manager.SetDynamicDomains(name, nil)
	dm.saveState()

	slog.Info("Domain source removed", "service", name)
}

// RefreshAll triggers an immediate re-poll of every domain source and returns
// how many sources were nudged.
func (dm *DynamicDomainManager) RefreshAll() int {
	dm.mu.Lock()
	sources := make([]*domainSource, 0, len(dm.sources))
	for _, source := range dm.sources {
		sources = append(sources, source)
	}
	dm.mu.Unlock()

	for _, source := range sources {
		source.Refresh()
	}
	return len(sources)
}

// Retry clears issuance holds and asks for the affected domains to be issued
// again, returning how many holds it cleared. An empty domain clears them all.
//
// This is the operator's escape hatch, and it is deliberately blunter than the
// release prober. It clears rate-limit holds, which the prober may never lift:
// an operator who knows the CA's window has passed should not have to wait on
// a retry time parsed out of an error string. It also wipes the failure
// history rather than only the hold, because asking for a retry is a claim
// that the underlying problem is fixed. The issuance rate limit still applies,
// so this cannot be used to hammer the CA.
func (dm *DynamicDomainManager) Retry(domain string) int {
	held := []string{}
	for candidate := range dm.quarantine.Snapshot() {
		if domain == "" || candidate == domain {
			held = append(held, candidate)
		}
	}

	for _, candidate := range held {
		dm.quarantine.Clear(candidate)
	}

	if len(held) == 0 {
		return 0
	}

	slog.Info("Cleared issuance holds on request", "domains", held)
	dm.saveState()

	for _, candidate := range held {
		dm.requestIssuanceAfterRelease(candidate)
	}
	return len(held)
}

// HasSources reports whether any service has a domain source configured.
func (dm *DynamicDomainManager) HasSources() bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	return len(dm.sources) > 0
}

// Status reports the dynamic domain subsystem's state for the domains CLI.
func (dm *DynamicDomainManager) Status() DomainsStatusResponse {
	dm.mu.Lock()
	states := make(map[string]*serviceDomainState, len(dm.states))
	settings := make(map[string]serviceSettings, len(dm.settings))
	heldRemovals := make(map[string][]string, len(dm.holds))
	for name, state := range dm.states {
		states[name] = state
		settings[name] = dm.settings[name]
		if hold := dm.holds[name]; hold != nil {
			heldRemovals[name] = append([]string{}, hold.removals...)
		}
	}
	dm.mu.Unlock()

	services := make(map[string]DomainsServiceStatus, len(states))
	for name, state := range states {
		domains := make([]DomainStatus, 0, len(state.Domains))
		for _, domain := range state.Domains {
			domains = append(domains, DomainStatus{
				Domain:    domain,
				Certified: dm.manager.HasValidCertificate(domain),
			})
		}

		services[name] = DomainsServiceStatus{
			Source:       settings[name].source,
			Domains:      domains,
			FetchedAt:    state.FetchedAt,
			HeldRemovals: heldRemovals[name],
		}
	}

	quarantine := map[string]QuarantineStatus{}
	for domain, entry := range dm.quarantine.Snapshot() {
		quarantine[domain] = QuarantineStatus{
			Until:    entry.Until,
			Failures: entry.Failures,
			Kind:     entry.Kind.String(),
		}
	}

	return DomainsStatusResponse{
		Services:     services,
		QueueLength:  dm.issuer.QueueLen(),
		Quarantine:   quarantine,
		Certificates: len(dm.manager.ManagedCertificates()),
		Registered:   dm.manager.RegisteredDomains(),
	}
}

// Private

// applyDomains installs a freshly fetched domain set for a service: updates
// the allowlist, clears quarantine history for removed domains, requests
// issuance for uncovered ones, and persists. A poll that removes more than
// shrinkGuardThreshold of the applied set has its removals held until
// consecutive polls confirm them; its additions still apply.
func (dm *DynamicDomainManager) applyDomains(service string, domains []string) {
	// A deploy/remove race can leave an orphaned poller behind; never apply
	// domains for a service the router no longer knows.
	if dm.resolver.serviceForName(service) == nil {
		slog.Debug("Ignoring domain update for unknown service", "service", service)
		return
	}

	dm.mu.Lock()
	// A poll can complete while its service is being removed or replaced;
	// applying it would resurrect state for a dead service.
	if _, ok := dm.sources[service]; !ok {
		dm.mu.Unlock()
		slog.Debug("Ignoring domain update for removed service", "service", service)
		return
	}

	previous := []string{}
	if state := dm.states[service]; state != nil {
		previous = state.Domains
	}

	added, removed := diffDomains(previous, domains)

	applying := domains
	held := dm.evaluateShrinkHold(service, previous, removed)
	if held {
		// Keep the previous set alive alongside whatever the poll added; the
		// polled set replaces it only once the shrink is confirmed.
		applying = append(append([]string{}, previous...), added...)

		// A held response must not park behind its own ETag: an unchanged
		// source would answer 304 forever, the body would never be re-fetched,
		// and the confirmation count could never advance.
		if source := dm.sources[service]; source != nil {
			source.SeedETag("")
		}
	}

	etag := ""
	if source := dm.sources[service]; source != nil {
		etag = source.ETag()
	}

	dm.states[service] = &serviceDomainState{
		Domains:   applying,
		ETag:      etag,
		FetchedAt: time.Now(),
	}
	dm.mu.Unlock()

	dm.manager.SetDynamicDomains(service, applying)

	if held {
		slog.Warn("Holding suspicious mass-removal from domain source",
			"service", service, "previous", len(previous), "polled", len(domains),
			"held_removals", len(removed), "confirmations_needed", shrinkGuardConfirmations)
	} else {
		for _, domain := range removed {
			dm.quarantine.Clear(domain)
		}
	}

	// Issuance follows the polled list, not the held union: a name the source
	// stopped reporting keeps its allowlist entry and any live certificate,
	// but earns no new ACME orders while its removal is in question.
	for _, domain := range domains {
		if !dm.manager.HasValidCertificate(domain) {
			dm.issuer.Request(domain, service)
		}
	}

	if !held && (len(added) > 0 || len(removed) > 0) {
		slog.Info("Domain source updated", "service", service,
			"domains", len(domains), "added", len(added), "removed", len(removed))
	}

	dm.saveState()
}

// shrinkHold tracks a suspicious mass-removal awaiting confirmation.
type shrinkHold struct {
	removals []string
	polls    int
}

// evaluateShrinkHold decides whether a poll's removals are applied or held.
// It must be called with dm.mu held. A poll below the threshold — including
// one that brings the domains back — clears any hold and applies normally.
func (dm *DynamicDomainManager) evaluateShrinkHold(service string, previous, removed []string) bool {
	if float64(len(removed)) <= shrinkGuardThreshold*float64(len(previous)) {
		delete(dm.holds, service)
		return false
	}

	hold := dm.holds[service]
	if hold == nil {
		hold = &shrinkHold{}
		dm.holds[service] = hold
	}
	hold.polls++
	hold.removals = removed

	if hold.polls >= shrinkGuardConfirmations {
		delete(dm.holds, service)
		return false
	}
	return true
}

// endpointFor resolves a healthy target for path-mode sources at poll time.
func (dm *DynamicDomainManager) endpointFor(service string) func() (string, string, error) {
	return func() (string, string, error) {
		dm.mu.Lock()
		host := dm.settings[service].host
		dm.mu.Unlock()

		svc := dm.resolver.serviceForName(service)
		if svc == nil {
			return "", "", fmt.Errorf("service %q not found", service)
		}

		lb := svc.ActiveLoadBalancer()
		if lb == nil {
			return "", "", fmt.Errorf("service %q has no active targets", service)
		}

		targets := lb.HealthyTargets()
		if len(targets) == 0 {
			return "", "", fmt.Errorf("service %q has no healthy targets", service)
		}

		return "http://" + targets[0].Address(), host, nil
	}
}

func (dm *DynamicDomainManager) batchSizeFor(service string) int {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	return dm.settings[service].batchSize
}

// preflightProbe checks that a domain routes back to this proxy before the
// first issuance attempt, so unreachable domains never burn an ACME order.
func (dm *DynamicDomainManager) preflightProbe(domain string) error {
	url := "http://" + domain + preflightPathPrefix + dm.preflightNonce

	resp, err := dm.probeClient.Get(url)
	if err != nil {
		return fmt.Errorf("pre-flight probe failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pre-flight probe returned status %d", resp.StatusCode)
	}

	body := make([]byte, len(dm.preflightNonce)+1)
	n, _ := resp.Body.Read(body)
	if strings.TrimSpace(string(body[:n])) != dm.preflightNonce {
		return fmt.Errorf("pre-flight probe reached a different server")
	}

	return nil
}

// diffDomains returns the entries added to and removed from a domain set.
func diffDomains(previous, current []string) (added, removed []string) {
	prevSet := make(map[string]struct{}, len(previous))
	for _, domain := range previous {
		prevSet[domain] = struct{}{}
	}
	currentSet := make(map[string]struct{}, len(current))
	for _, domain := range current {
		currentSet[domain] = struct{}{}
	}

	for _, domain := range current {
		if _, ok := prevSet[domain]; !ok {
			added = append(added, domain)
		}
	}
	for _, domain := range previous {
		if _, ok := currentSet[domain]; !ok {
			removed = append(removed, domain)
		}
	}
	return added, removed
}

func generateNonce() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("unable to generate preflight nonce: %v", err))
	}
	return hex.EncodeToString(buffer)
}

// managerObtainer defers to the SAN manager's ACME client, which only exists
// after Initialize.
type managerObtainer struct {
	manager *SANCertManager
}

// Obtain routes through the manager's issuance strategy, so dynamic domains get
// DNS-01 when a provider is configured -- and the same allowlist and rate limit
// either way.
func (o managerObtainer) Obtain(request certificate.ObtainRequest) (*certificate.Resource, error) {
	return o.manager.obtainCertificate(request)
}

// ObtainAt pins the order to a directory the caller already resolved; the
// renewer uses it so a partition keeps its certificate's identity even when
// the domains' owners are temporarily unresolvable.
func (o managerObtainer) ObtainAt(directory string, request certificate.ObtainRequest) (*certificate.Resource, error) {
	return o.manager.obtainCertificateAt(directory, request)
}

// GetRenewalInfo asks the identity that issued the certificate — a staging
// cert's ARI lives at the staging CA, not the run-level one.
func (o managerObtainer) GetRenewalInfo(request certificate.RenewalInfoRequest) (*certificate.RenewalInfoResponse, error) {
	var domains []string
	if request.Cert != nil {
		domains = request.Cert.DNSNames
	}

	obtainer := o.manager.renewalInfoObtainer(domains)
	if obtainer == nil {
		return nil, ErrManagerNotReady
	}
	return obtainer.GetRenewalInfo(request)
}
