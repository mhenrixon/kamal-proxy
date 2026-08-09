package server

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

const (
	// DefaultRedirectsInterval is how often a redirects source is polled when
	// no interval is configured.
	DefaultRedirectsInterval = 5 * time.Minute

	// MinRedirectsInterval protects the app from being hammered by polls.
	MinRedirectsInterval = 10 * time.Second
)

// DynamicRedirectConfig configures the dynamic redirect subsystem.
type DynamicRedirectConfig struct {
	// StatePath is where the last good redirect maps are persisted, so a
	// reboot serves redirects before the first poll completes.
	StatePath string

	// RefreshToken authorizes POST /.kamal-proxy/redirects/refresh. Empty
	// disables the endpoint.
	RefreshToken string

	// SourceToken, when set, is sent as a bearer token with redirects source
	// polls.
	SourceToken string
}

// redirectServiceSettings caches the per-service options captured at deploy
// time, so background goroutines never read live ServiceOptions.
type redirectServiceSettings struct {
	source   string
	interval time.Duration
	host     string
}

// DynamicRedirectManager coordinates the dynamic redirect subsystem: one
// poller per service with a redirects source, the compiled-map handoff to the
// service, and state persistence. It deliberately mirrors
// DynamicDomainManager, which solved the same shape for certificates.
type DynamicRedirectManager struct {
	config   DynamicRedirectConfig
	resolver serviceResolver

	mu          sync.Mutex
	sources     map[string]*sourcePoller
	settings    map[string]redirectServiceSettings
	states      map[string]*serviceRedirectState
	lastRefresh time.Time
}

func NewDynamicRedirectManager(config DynamicRedirectConfig, resolver serviceResolver) *DynamicRedirectManager {
	dm := &DynamicRedirectManager{
		config:   config,
		resolver: resolver,
		sources:  make(map[string]*sourcePoller),
		settings: make(map[string]redirectServiceSettings),
		states:   make(map[string]*serviceRedirectState),
	}

	dm.loadState()

	return dm
}

// Stop shuts down the pollers and persists state.
func (dm *DynamicRedirectManager) Stop() {
	dm.mu.Lock()
	sources := make([]*sourcePoller, 0, len(dm.sources))
	for _, source := range dm.sources {
		sources = append(sources, source)
	}
	dm.mu.Unlock()

	for _, source := range sources {
		source.Stop()
	}

	dm.saveState()
}

// ServiceDeployed reconciles a service's redirects source after a deploy. A
// service without a source has any previous source removed and its dynamic
// redirects evicted.
func (dm *DynamicRedirectManager) ServiceDeployed(name string, options ServiceOptions) {
	if options.RedirectsSource == "" {
		dm.ServiceRemoved(name)
		return
	}

	host := ""
	if options.HasConfiguredHosts() {
		host = options.Hosts[0]
	}

	dm.mu.Lock()

	previous := dm.sources[name]
	dm.settings[name] = redirectServiceSettings{
		source:   options.RedirectsSource,
		interval: options.RedirectsInterval,
		host:     host,
	}

	state := dm.states[name]
	if state == nil {
		state = &serviceRedirectState{}
		dm.states[name] = state
	}

	interval := options.RedirectsInterval
	if interval == 0 {
		interval = DefaultRedirectsInterval
	}

	source := newSourcePoller(sourcePollerConfig{
		Service:  name,
		Kind:     "redirects source",
		Source:   options.RedirectsSource,
		Interval: interval,
		Token:    dm.config.SourceToken,
		Endpoint: dm.endpointFor(name),
		OnBody:   func(body io.Reader) error { return dm.applyPayload(name, body) },
	})
	source.SeedETag(state.ETag)
	dm.sources[name] = source

	persisted := state.Hosts
	dm.mu.Unlock()

	if previous != nil {
		previous.Stop()
	}

	// Serve the persisted map immediately; the first poll reconciles.
	if len(persisted) > 0 {
		dm.installMap(name, persisted)
	}

	source.Start()

	slog.Info("Redirects source configured", "service", name, "source", options.RedirectsSource,
		"persisted_hosts", len(persisted))
}

// ServiceRemoved stops a service's poller and evicts its dynamic redirects.
func (dm *DynamicRedirectManager) ServiceRemoved(name string) {
	dm.mu.Lock()
	source := dm.sources[name]
	state := dm.states[name]
	delete(dm.sources, name)
	delete(dm.settings, name)
	delete(dm.states, name)
	dm.mu.Unlock()

	if source == nil && state == nil {
		return
	}

	if source != nil {
		source.Stop()
	}

	if service := dm.resolver.serviceForName(name); service != nil {
		service.SetDynamicRedirects(nil)
	}
	metrics.Tracker.SetDynamicRedirects(name, 0, 0)

	dm.saveState()

	slog.Info("Redirects source removed", "service", name)
}

// RefreshAll triggers an immediate re-poll of every redirects source and
// returns how many sources were nudged.
func (dm *DynamicRedirectManager) RefreshAll() int {
	dm.mu.Lock()
	sources := make([]*sourcePoller, 0, len(dm.sources))
	for _, source := range dm.sources {
		sources = append(sources, source)
	}
	dm.mu.Unlock()

	for _, source := range sources {
		source.Refresh()
	}
	return len(sources)
}

// HasSources reports whether any service has a redirects source configured.
func (dm *DynamicRedirectManager) HasSources() bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	return len(dm.sources) > 0
}

// Private

// applyPayload parses and installs one fetched payload. Returning an error
// keeps the last good map serving and rolls the poller's ETag back, so a
// broken payload is retried rather than silently accepted.
func (dm *DynamicRedirectManager) applyPayload(service string, body io.Reader) error {
	hosts, err := parseRedirectPayload(body)
	if err != nil {
		metrics.Tracker.TrackDynamicRedirectPoll(service, "rejected")
		return err
	}

	// A deploy/remove race can leave an orphaned poller behind; never apply
	// redirects for a service the router no longer knows.
	svc := dm.resolver.serviceForName(service)
	if svc == nil {
		slog.Debug("Ignoring redirect update for unknown service", "service", service)
		return nil
	}

	compiled := compileRedirectMap(hosts)
	hostCount, ruleCount := compiled.counts()
	if hostCount == 0 {
		// Parseable but nothing survived validation: treat it like an invalid
		// payload rather than wiping live redirects with garbage.
		metrics.Tracker.TrackDynamicRedirectPoll(service, "rejected")
		return fmt.Errorf("redirect list has no valid hosts; keeping the previous map")
	}

	dm.mu.Lock()
	// A poll can complete while its service is being removed or replaced;
	// applying it would resurrect state for a dead service.
	source, ok := dm.sources[service]
	if !ok {
		dm.mu.Unlock()
		slog.Debug("Ignoring redirect update for removed service", "service", service)
		return nil
	}

	dm.states[service] = &serviceRedirectState{
		Hosts:     hosts,
		ETag:      source.ETag(),
		FetchedAt: time.Now(),
	}
	dm.mu.Unlock()

	svc.SetDynamicRedirects(compiled)
	metrics.Tracker.SetDynamicRedirects(service, hostCount, ruleCount)
	metrics.Tracker.TrackDynamicRedirectPoll(service, "applied")

	slog.Info("Redirects source updated", "service", service, "hosts", hostCount, "rules", ruleCount)

	dm.saveState()
	return nil
}

// installMap compiles and hands a persisted host map to its service.
func (dm *DynamicRedirectManager) installMap(service string, hosts map[string]redirectHostConfig) {
	svc := dm.resolver.serviceForName(service)
	if svc == nil {
		return
	}

	compiled := compileRedirectMap(hosts)
	svc.SetDynamicRedirects(compiled)

	hostCount, ruleCount := compiled.counts()
	metrics.Tracker.SetDynamicRedirects(service, hostCount, ruleCount)
}

// endpointFor resolves a healthy target for path-mode sources at poll time.
func (dm *DynamicRedirectManager) endpointFor(service string) func() (string, string, error) {
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
