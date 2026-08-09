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

// DynamicRedirectManager coordinates the dynamic redirect subsystem: one
// poller per service with a redirects source, the compiled-map handoff to the
// service, and state persistence. It deliberately mirrors
// DynamicDomainManager, which solved the same shape for certificates.
type DynamicRedirectManager struct {
	config   DynamicRedirectConfig
	resolver serviceResolver

	mu          sync.Mutex
	sources     map[string]*sourcePoller
	hosts       map[string]string // service -> Host header for path-mode polls
	states      map[string]*serviceRedirectState
	counts      map[string][2]int // service -> {hosts, rules} last installed
	lastRefresh time.Time

	// saveLock serializes state writes: concurrent polls share one temp file
	// path, and interleaved writers would tear it despite the atomic rename.
	saveLock sync.Mutex
}

func NewDynamicRedirectManager(config DynamicRedirectConfig, resolver serviceResolver) *DynamicRedirectManager {
	dm := &DynamicRedirectManager{
		config:   config,
		resolver: resolver,
		sources:  make(map[string]*sourcePoller),
		hosts:    make(map[string]string),
		states:   make(map[string]*serviceRedirectState),
		counts:   make(map[string][2]int),
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
	dm.hosts[name] = host

	state := dm.states[name]
	if state == nil {
		state = &serviceRedirectState{}
		dm.states[name] = state
	}

	// The persisted map keeps serving across a source change, but its ETag
	// belongs to the old resource: seeding it could let the new source answer
	// 304 to a tag it never issued, freezing the old redirects in place.
	if state.Source != options.RedirectsSource {
		state.ETag = ""
		state.Source = options.RedirectsSource
	}

	interval := options.RedirectsInterval
	if interval == 0 {
		interval = DefaultRedirectsInterval
	}

	// The closure captures the poller variable so applyPayload can refuse
	// payloads from a superseded poller: an in-flight poll from the previous
	// deployment must not overwrite the new source's state.
	var source *sourcePoller
	source = newSourcePoller(sourcePollerConfig{
		Service:     name,
		Kind:        "redirects source",
		Source:      options.RedirectsSource,
		Interval:    interval,
		Token:       dm.config.SourceToken,
		Endpoint:    dm.endpointFor(name),
		OnBody:      func(body io.Reader) error { return dm.applyPayload(name, source, body) },
		OnPollError: func() { metrics.Tracker.TrackDynamicRedirectPoll(name, "error") },
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
	delete(dm.hosts, name)
	delete(dm.states, name)
	delete(dm.counts, name)
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

// PublishMetrics re-emits the map size gauges. Maps restored from state are
// installed before the metrics endpoint exists, so run.go calls this once the
// server is up; without it a proxy serving only persisted redirects reports
// no map at all.
func (dm *DynamicRedirectManager) PublishMetrics() {
	dm.mu.Lock()
	counts := make(map[string][2]int, len(dm.counts))
	for service, count := range dm.counts {
		counts[service] = count
	}
	dm.mu.Unlock()

	for service, count := range counts {
		metrics.Tracker.SetDynamicRedirects(service, count[0], count[1])
	}
}

// Private

// applyPayload parses and installs one fetched payload. An explicit empty map
// clears the service's redirects; a malformed payload returns an error, which
// keeps the last good map serving and rolls the poller's ETag back so the
// payload is retried rather than silently accepted.
func (dm *DynamicRedirectManager) applyPayload(service string, from *sourcePoller, body io.Reader) error {
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
	if len(hosts) > 0 && hostCount == 0 {
		// Parseable but nothing survived validation: treat it like an invalid
		// payload rather than wiping live redirects with garbage. An explicit
		// empty map is the sanctioned way to clear.
		metrics.Tracker.TrackDynamicRedirectPoll(service, "rejected")
		return fmt.Errorf("redirect list has no valid hosts; keeping the previous map")
	}

	var install *dynamicRedirectMap
	if hostCount > 0 {
		install = compiled
	}

	dm.mu.Lock()
	// A poll can complete while its poller is being replaced or removed;
	// applying it would resurrect state for a dead deployment.
	if dm.sources[service] != from {
		dm.mu.Unlock()
		slog.Debug("Ignoring redirect update from superseded poller", "service", service)
		return nil
	}

	dm.states[service] = &serviceRedirectState{
		Hosts:     hosts,
		ETag:      from.ETag(),
		FetchedAt: time.Now(),
		Source:    from.config.Source,
	}
	dm.counts[service] = [2]int{hostCount, ruleCount}
	dm.mu.Unlock()

	svc.SetDynamicRedirects(install)
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
	dm.mu.Lock()
	dm.counts[service] = [2]int{hostCount, ruleCount}
	dm.mu.Unlock()
	metrics.Tracker.SetDynamicRedirects(service, hostCount, ruleCount)
}

// endpointFor resolves a healthy target for path-mode sources at poll time.
func (dm *DynamicRedirectManager) endpointFor(service string) func() (string, string, error) {
	return func() (string, string, error) {
		dm.mu.Lock()
		host := dm.hosts[service]
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
