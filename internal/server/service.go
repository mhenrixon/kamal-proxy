package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

const (
	B  int64 = 1
	KB       = B << 10
	MB       = KB << 10
	GB       = MB << 10
)

const (
	DefaultDeployTimeout         = time.Second * 30
	DefaultDrainTimeout          = time.Second * 30
	DefaultPauseTimeout          = time.Second * 30
	DefaultWriterAffinityTimeout = time.Second

	DefaultHealthCheckPath     = "/up"
	DefaultHealthCheckPort     = 0
	DefaultHealthCheckInterval = time.Second
	DefaultHealthCheckTimeout  = time.Second * 5

	MaxIdleConnsPerHost = 100
	ProxyBufferSize     = 32 * KB

	DefaultTargetTimeout       = time.Second * 30
	DefaultMaxMemoryBufferSize = 1 * MB
	DefaultMaxRequestBodySize  = 0
	DefaultMaxResponseBodySize = 0

	DefaultStopMessage = ""
)

var (
	ErrorRolloutTargetNotSet                 = errors.New("rollout target not set")
	ErrorUnableToLoadErrorPages              = errors.New("unable to load error pages")
	ErrorAutomaticTLSDoesNotSupportWildcards = errors.New("automatic TLS does not support wildcards")
	ErrServiceOptionsInvalid                 = errors.New("service options invalid")

	contextKeyInternalRequest = contextKey("internal-request")
)

// markInternalRequest marks the context as belonging to an internal request:
// one synthesized inside the proxy itself, such as a TLS on-demand check
// probe, rather than arriving over a client connection.
func markInternalRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyInternalRequest, true)
}

func isInternalRequest(r *http.Request) bool {
	internal, _ := r.Context().Value(contextKeyInternalRequest).(bool)
	return internal
}

type TargetSlot int

const (
	TargetSlotActive TargetSlot = iota
	TargetSlotRollout
)

type HealthCheckConfig struct {
	Path     string        `json:"path"`
	Port     int           `json:"port"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Host     string        `json:"host"`
}

type DeploymentOptions struct {
	DeployTimeout time.Duration
	DrainTimeout  time.Duration
	Force         bool
}

type ServiceOptions struct {
	Hosts                       []string      `json:"hosts"`
	PathPrefixes                []string      `json:"path_prefixes"`
	TLSEnabled                  bool          `json:"tls_enabled"`
	TLSCertificatePath          string        `json:"tls_certificate_path"`
	TLSPrivateKeyPath           string        `json:"tls_private_key_path"`
	TLSOnDemandURL              string        `json:"tls_on_demand_url"`
	TLSRedirect                 bool          `json:"tls_redirect"`
	CanonicalHost               string        `json:"canonical_host"`
	ACMEDirectory               string        `json:"acme_directory"`
	ACMECachePath               string        `json:"acme_cache_path"`
	ErrorPagePath               string        `json:"error_page_path"`
	StripPrefix                 bool          `json:"strip_prefix"`
	WriterAffinityTimeout       time.Duration `json:"writer_affinity_timeout"`
	ReadTargetsAcceptWebsockets bool          `json:"read_targets_accept_websockets"`
	ExcludeMetricsPaths         []string      `json:"exclude_metrics_paths"`
	ClientIPHeader              string        `json:"client_ip_header"`
	// TLSClientCACertificatePath is a PEM bundle of certificate authorities that
	// client certificates must chain to. Set, it turns on mTLS for the hosts this
	// service serves; empty (the default) leaves the handshake untouched.
	TLSClientCACertificatePath string        `json:"tls_client_ca_certificate_path,omitempty"`
	TLSDomainsSource           string        `json:"tls_domains_source,omitempty"`
	TLSDomainsInterval         time.Duration `json:"tls_domains_interval,omitempty"`
	TLSDomainsBatchSize        int           `json:"tls_domains_batch_size,omitempty"`

	// InterceptErrorStatuses lists the response statuses the target itself may
	// return that should be replaced with the proxy's error pages. Empty (the
	// default) passes every target response through untouched.
	InterceptErrorStatuses []int `json:"intercept_error_statuses,omitempty"`

	// TargetTryDuration bounds how long the load balancer keeps trying to place
	// a request on a healthy target. Zero (the default) makes a single attempt.
	TargetTryDuration time.Duration `json:"target_try_duration,omitempty"`
	// TargetTryInterval is the pause between those attempts. Zero uses
	// DefaultTargetTryInterval.
	TargetTryInterval time.Duration `json:"target_try_interval,omitempty"`

	// SessionAffinity keeps each client on the target that first served it, for
	// apps holding session state in the instance. False (the default) rotates
	// every request, as the proxy always has. See session_affinity.go.
	SessionAffinity bool `json:"session_affinity,omitempty"`
	// SessionAffinityCookieName names the pin cookie. Empty uses
	// DefaultSessionAffinityCookieName.
	SessionAffinityCookieName string `json:"session_affinity_cookie_name,omitempty"`

	// BasicAuth requires HTTP Basic credentials on every request to this
	// service, stored as "<scheme>:<hex salt>:<hex digest>" over
	// "<username>:<password>". The CLI does the hashing, so no plaintext
	// credential crosses the RPC socket or reaches the state file. Empty (the
	// default) leaves the service open.
	BasicAuth string `json:"basic_auth,omitempty"`

	// AllowIPs restricts this service to the given addresses and CIDR ranges.
	// Empty (the default) serves everyone. See ip_allow_list.go for which
	// address is matched and why.
	AllowIPs []string `json:"allow_ips,omitempty"`
	// TrustedProxies names the proxies in front of this one, allowing AllowIPs
	// and the rate limit to be matched against the forwarded chain rather than
	// the connecting peer.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// RateLimit caps how many requests per second a single client may make to
	// this service. Zero (the default) does not limit anything. See
	// rate_limit.go for what counts as one client.
	RateLimit float64 `json:"rate_limit,omitempty"`
	// RateLimitBurst is how many requests a client may make back to back before
	// the rate applies. Zero uses the rate rounded up, so a limit reads as
	// "n per second" without a second flag.
	RateLimitBurst int `json:"rate_limit_burst,omitempty"`
	// RateLimitExempt lists addresses and CIDR ranges the limit does not apply
	// to, such as monitoring or an internal network.
	RateLimitExempt []string `json:"rate_limit_exempt,omitempty"`

	// Redirects answer a matching request with a Location; Rewrites change only
	// the path the target receives. See redirect_rules.go.
	Redirects []PathRule `json:"redirects,omitempty"`
	Rewrites  []PathRule `json:"rewrites,omitempty"`

	// SleepAfter stops this service's containers after this long with no traffic,
	// starting them again on the next request. Zero (the default) never sleeps.
	SleepAfter time.Duration `json:"sleep_after,omitempty"`
	// WakeTimeout bounds how long a request is held while those containers start
	// and pass a health check. Zero means DefaultWakeTimeout.
	WakeTimeout time.Duration `json:"wake_timeout,omitempty"`
	// SleepContainers names the containers to stop and start, replacing what the
	// proxy infers from the target addresses. Needed when a target names a network
	// alias rather than a container.
	SleepContainers []string `json:"sleep_containers,omitempty"`

	// Compression encodes responses on their way back to the client. A zero
	// value leaves them alone, which is what every state file written before
	// this option existed restores to.
	Compression CompressionOptions `json:"compression,omitzero"`

	// Cache stores responses the target marks `public` and answers later
	// requests from them. A zero value keeps the cache off. See
	// cache_options.go.
	Cache CacheOptions `json:"cache,omitzero"`
}

func (so *ServiceOptions) ShouldExcludeMetrics(r *http.Request) bool {
	return slices.Contains(so.ExcludeMetricsPaths, RoutedTargetPath(r))
}

func (so *ServiceOptions) Normalize() {
	so.Hosts = NormalizeHosts(so.Hosts)
	so.PathPrefixes = NormalizePathPrefixes(so.PathPrefixes)
	so.Compression.Normalize()
	so.Cache.Normalize()

	// The cobra default makes --help honest; this is what gives restored state
	// files and direct RPC callers the same value. Only zero defaults: a negative
	// is a typo, and silently turning it into 30s would hide it -- validateSleep
	// rejects it instead.
	if so.SleepAfter > 0 && so.WakeTimeout == 0 {
		so.WakeTimeout = DefaultWakeTimeout
	}
}

func (so ServiceOptions) Validate() error {
	so.Normalize()

	if so.TLSOnDemandURL != "" && !so.TLSEnabled {
		return fmt.Errorf("%w: TLS must be enabled to use a TLS on-demand URL", ErrServiceOptionsInvalid)
	}

	if so.TLSClientCACertificatePath != "" && !so.TLSEnabled {
		return fmt.Errorf("%w: TLS must be enabled to require client certificates", ErrServiceOptionsInvalid)
	}

	if so.TLSEnabled {
		if so.TLSOnDemandURL != "" {
			if so.HasConfiguredHosts() {
				return fmt.Errorf("%w: cannot set hosts when using a TLS on-demand URL", ErrServiceOptionsInvalid)
			}

			if so.TLSCertificatePath != "" || so.TLSPrivateKeyPath != "" {
				return fmt.Errorf("%w: cannot use a custom TLS certificate with a TLS on-demand URL", ErrServiceOptionsInvalid)
			}

			if so.CanonicalHost != "" {
				return fmt.Errorf("%w: cannot set a canonical host when using a TLS on-demand URL", ErrServiceOptionsInvalid)
			}

			if err := validateTLSOnDemandURL(so.TLSOnDemandURL); err != nil {
				return fmt.Errorf("%w: %w", ErrServiceOptionsInvalid, err)
			}
		} else if !so.HasConfiguredHosts() && so.TLSDomainsSource == "" {
			return fmt.Errorf("%w: host must be set when using TLS", ErrServiceOptionsInvalid)
		}

		if !slices.Contains(so.PathPrefixes, rootPath) {
			return fmt.Errorf("%w: TLS settings must be specified on the root path service", ErrServiceOptionsInvalid)
		}
	}

	if so.CanonicalHost != "" && len(so.Hosts) > 0 && so.Hosts[0] != "" {
		if !slices.Contains(so.Hosts, so.CanonicalHost) {
			return fmt.Errorf("%w: canonical-host '%s' must be present in the hosts list: %v", ErrServiceOptionsInvalid, so.CanonicalHost, so.Hosts)
		}
	}

	if err := so.validateInterceptErrorStatuses(); err != nil {
		return err
	}

	if err := so.validateRetries(); err != nil {
		return err
	}

	if err := so.validateSessionAffinity(); err != nil {
		return err
	}

	if err := so.validateBasicAuth(); err != nil {
		return err
	}

	if err := so.validateAllowIPs(); err != nil {
		return err
	}

	if err := so.validateRateLimit(); err != nil {
		return err
	}

	if err := so.validatePathRules(); err != nil {
		return err
	}

	if err := so.Compression.Validate(); err != nil {
		return err
	}

	if err := so.Cache.Validate(); err != nil {
		return err
	}

	if err := so.validateSleep(); err != nil {
		return err
	}

	return so.validateDynamicDomains()
}

func (so *ServiceOptions) WithHosts(hosts []string) ServiceOptions {
	options := *so
	options.Hosts = hosts
	return options
}

func (so ServiceOptions) HasConfiguredHosts() bool {
	return len(so.Hosts) > 0 && !slices.Contains(so.Hosts, "")
}

func (so *ServiceOptions) WithPathPrefixes(pathPrefixes []string) ServiceOptions {
	options := *so
	options.PathPrefixes = pathPrefixes
	return options
}

func (so ServiceOptions) ScopedCachePath() string {
	// We need to scope our certificate cache according to whatever ACME settings
	// we want to use, such as the directory.  This is so we can reuse
	// certificates between deployments when the settings are the same, but
	// provision new certificates when they change.

	hasher := sha256.New()
	hasher.Write([]byte(so.ACMEDirectory))
	hash := hex.EncodeToString(hasher.Sum(nil))

	return path.Join(so.ACMECachePath, hash)
}

type Service struct {
	name          string
	options       ServiceOptions
	targetOptions TargetOptions

	active      *LoadBalancer
	rollout     *LoadBalancer
	serviceLock sync.RWMutex

	pauseController   *PauseController
	rolloutController *RolloutController

	sanCertManager *SANCertManager
	certManager    CertManager
	clientCAs      *x509.CertPool
	middleware     http.Handler
	basicAuth      *basicAuthCredential
	allowedIPs     *ipAllowList
	rateLimiter    *rateLimiter
	redirects      *pathRuleSet
	rewrites       *pathRuleSet

	// cacheStore is shared with every other service on this proxy, and possibly
	// with every other proxy in the fleet. cacheHandler is this service's own
	// entry into it, sitting between the checks above and the load balancer.
	cacheStore   CacheStore
	cacheHandler http.Handler

	lifecycle         ContainerLifecycle
	idleController    *IdleController
	restoredIdleState IdleState
	statePersister    func()
}

func NewService(name string, options ServiceOptions, targetOptions TargetOptions, sanCertManager *SANCertManager) (*Service, error) {
	service := &Service{
		name:            name,
		pauseController: NewPauseController(),
		sanCertManager:  sanCertManager,
	}

	if err := service.initialize(options, targetOptions); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *Service) UpdateOptions(options ServiceOptions, targetOptions TargetOptions) error {
	return s.initialize(options, targetOptions)
}

func (s *Service) SetSANCertManager(manager *SANCertManager) {
	prevCertManager := s.certManager
	prevMiddleware := s.middleware

	s.sanCertManager = manager
	if s.options.TLSEnabled && s.options.TLSCertificatePath == "" {
		if err := s.initialize(s.options, s.targetOptions); err != nil {
			slog.Error("Failed to reinitialize service with SAN cert manager, keeping previous TLS config",
				"service", s.name, "error", err)
			s.certManager = prevCertManager
			s.middleware = prevMiddleware
		}
	}
}

func (s *Service) Dispose() {
	if s.idleController != nil {
		s.idleController.Close()
	}

	if s.active != nil {
		s.active.Dispose()
	}
	if s.rollout != nil {
		s.rollout.Dispose()
	}
}

// ActiveLoadBalancer returns the service's active load balancer, if any.
func (s *Service) ActiveLoadBalancer() *LoadBalancer {
	s.serviceLock.RLock()
	defer s.serviceLock.RUnlock()

	return s.active
}

func (s *Service) UpdateLoadBalancer(lb *LoadBalancer, slot TargetSlot) *LoadBalancer {
	s.serviceLock.Lock()
	defer s.serviceLock.Unlock()

	var replaced *LoadBalancer

	if slot == TargetSlotRollout {
		replaced = s.rollout
		s.rollout = lb
	} else {
		replaced = s.active
		s.active = lb
	}

	// Refs are derived from the targets, so they are only knowable once a load
	// balancer is installed -- initialize runs before that on a first deploy. A
	// redeploy pointing at new containers reaches here too, which is exactly when
	// the controller needs to be told.
	s.configureIdleController(s.options)

	return replaced
}

func (s *Service) SetRolloutSplit(percentage int, allowlist []string) error {
	s.serviceLock.Lock()
	defer s.serviceLock.Unlock()

	if s.rollout == nil {
		return ErrorRolloutTargetNotSet
	}

	s.rolloutController = NewRolloutController(percentage, allowlist)
	slog.Info("Set rollout split", "service", s.name, "percentage", percentage, "allowlist", allowlist)
	return nil
}

func (s *Service) StopRollout() error {
	s.serviceLock.Lock()
	defer s.serviceLock.Unlock()

	s.rolloutController = nil
	slog.Info("Stopped rollout", "service", s.name)
	return nil
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.options.ShouldExcludeMetrics(r) {
		LoggingRequestContext(r).ExcludeMetrics = true
	} else {
		metrics.Tracker.AddInflightRequest(s.name)
		defer metrics.Tracker.SubtractInflightRequest(s.name)
	}

	s.middleware.ServeHTTP(w, r)
}

type marshalledService struct {
	Name string `json:"name"`
	// IdleState is written as a name rather than an enum's number: the state file
	// outlives proxy versions and operators read it. Absent -- every state file
	// written before scale-to-zero existed -- parses to active, which is also what
	// SleepAfter == 0 produces, so the feature restores off.
	IdleState         string             `json:"idle_state,omitempty"`
	Options           ServiceOptions     `json:"options"`
	TargetOptions     TargetOptions      `json:"target_options"`
	ActiveTargets     []string           `json:"active_targets"`
	ActiveReaders     []string           `json:"active_readers"`
	RolloutTargets    []string           `json:"rollout_targets"`
	RolloutReaders    []string           `json:"rollout_readers"`
	PauseController   *PauseController   `json:"pause_controller"`
	RolloutController *RolloutController `json:"rollout_controller"`

	LegacyActiveTarget  string   `json:"active_target,omitempty"`
	LegacyRolloutTarget string   `json:"rollout_target,omitempty"`
	LegacyHosts         []string `json:"hosts,omitempty"`
	LegacyPathPrefixes  []string `json:"path_prefixes,omitempty"`
}

func (s *Service) MarshalJSON() ([]byte, error) {
	// Saving state marshals every service while deploys may be replacing their
	// load balancers: saveStateSnapshot holds only the router's read lock, and
	// UpdateLoadBalancer writes s.active and s.rollout under this one. Lock order
	// is routerLock then serviceLock, matching installLoadBalancer, so this
	// cannot invert.
	s.serviceLock.RLock()
	defer s.serviceLock.RUnlock()

	// Specs rather than Names, so that a target's weight survives a restart. It
	// renders as a bare address unless a weight was actually set, so unweighted
	// state files stay exactly what they have always been.
	var rolloutTargets []string
	var rolloutReaders []string
	if s.rollout != nil {
		rolloutTargets = s.rollout.WriteTargets().Specs()
		rolloutReaders = s.rollout.ReadTargets().Specs()
	}

	idleState := IdleStateActive
	if s.idleController != nil {
		idleState = s.idleController.State()
	}

	return json.Marshal(marshalledService{
		Name:              s.name,
		IdleState:         idleState.String(),
		ActiveTargets:     s.active.WriteTargets().Specs(),
		ActiveReaders:     s.active.ReadTargets().Specs(),
		RolloutTargets:    rolloutTargets,
		RolloutReaders:    rolloutReaders,
		Options:           s.options,
		TargetOptions:     s.targetOptions,
		PauseController:   s.pauseController,
		RolloutController: s.rolloutController,
	})
}

func (s *Service) UnmarshalJSON(data []byte) error {
	var ms marshalledService
	err := json.Unmarshal(data, &ms)
	if err != nil {
		return err
	}

	// Support previous version of service state
	if len(ms.ActiveTargets) == 0 && ms.LegacyActiveTarget != "" {
		ms.ActiveTargets = []string{ms.LegacyActiveTarget}
	}
	if len(ms.RolloutTargets) == 0 && ms.LegacyRolloutTarget != "" {
		ms.RolloutTargets = []string{ms.LegacyRolloutTarget}
	}
	if len(ms.Options.Hosts) == 0 && len(ms.LegacyHosts) > 0 {
		ms.Options.Hosts = ms.LegacyHosts
	}
	if len(ms.Options.PathPrefixes) == 0 && len(ms.LegacyPathPrefixes) > 0 {
		ms.Options.PathPrefixes = ms.LegacyPathPrefixes
	}
	ms.Options.Normalize()

	s.name = ms.Name
	s.pauseController = ms.PauseController
	s.rolloutController = ms.RolloutController

	activeTargets, err := NewTargetList(ms.ActiveTargets, ms.ActiveReaders, ms.TargetOptions)
	if err != nil {
		return err
	}
	s.active = NewLoadBalancer(activeTargets, ms.Options.WriterAffinityTimeout, ms.Options.ReadTargetsAcceptWebsockets).
		WithRetryPolicy(ms.Options.RetryPolicy()).
		WithSessionAffinity(ms.Options.SessionAffinityPolicy())
	s.active.MarkAllHealthy()

	rolloutTargets, err := NewTargetList(ms.RolloutTargets, ms.RolloutReaders, ms.TargetOptions)
	if err != nil {
		return err
	}
	if len(rolloutTargets) > 0 {
		s.rollout = NewLoadBalancer(rolloutTargets, ms.Options.WriterAffinityTimeout, ms.Options.ReadTargetsAcceptWebsockets).
			WithRetryPolicy(ms.Options.RetryPolicy()).
			WithSessionAffinity(ms.Options.SessionAffinityPolicy())
		s.rollout.MarkAllHealthy()
	}

	// Recorded, not acted on: the lifecycle is still nil here, so a controller
	// built now could reach StopContainer on a nil interface. SetContainerLifecycle
	// is what creates it, after the router has decoded the whole state file.
	s.restoredIdleState = ParseIdleState(ms.IdleState)

	return s.initialize(ms.Options, ms.TargetOptions)
}

func (s *Service) Stop(drainTimeout time.Duration, message string) error {
	err := s.pauseController.Stop(message)
	if err != nil {
		return err
	}

	slog.Info("Service stopped", "service", s.name)

	s.Drain(drainTimeout)
	slog.Info("Service drained", "service", s.name)
	return nil
}

func (s *Service) Pause(drainTimeout time.Duration, pauseTimeout time.Duration) error {
	err := s.pauseController.Pause(pauseTimeout)
	if err != nil {
		return err
	}

	slog.Info("Service paused", "service", s.name)

	s.Drain(drainTimeout)
	slog.Info("Service drained", "service", s.name)
	return nil
}

func (s *Service) Resume() error {
	err := s.pauseController.Resume()
	if err != nil {
		return err
	}

	slog.Info("Service resumed", "service", s.name)
	return nil
}

// Private

func (s *Service) initialize(options ServiceOptions, targetOptions TargetOptions) error {
	// Canonicalize before anything stores or serves them, so that persisted state
	// and the prefixes the deadline middleware matches on agree with each other.
	targetOptions.normalizePathTimeouts()

	certManager, err := s.createCertManager(options)
	if err != nil {
		return err
	}

	// Loaded here rather than at handshake time so a bad path fails the deploy.
	// Silently serving without client verification would be a security hole.
	clientCAs, err := s.createClientCAs(options)
	if err != nil {
		return err
	}

	middleware, err := s.createMiddleware(options, targetOptions, certManager)
	if err != nil {
		return err
	}

	redirects, rewrites, err := s.resolvePathRules(options)
	if err != nil {
		return err
	}

	s.redirects = redirects
	s.rewrites = rewrites
	s.cacheHandler = s.createCacheHandler(options)
	s.options = options
	s.targetOptions = targetOptions
	s.configureIdleController(options)
	s.certManager = certManager
	s.clientCAs = clientCAs
	s.middleware = middleware
	s.basicAuth = s.resolveBasicAuth(options)
	s.allowedIPs = s.resolveIPAllowList(options)
	s.rateLimiter = s.resolveRateLimiter(options)

	return nil
}

// RecheckTargetHealth re-verifies restored targets instead of trusting the
// saved state's assumption that they are still healthy.
func (s *Service) RecheckTargetHealth() {
	if s.active != nil {
		s.active.RecheckHealth()
	}
	if s.rollout != nil {
		s.rollout.RecheckHealth()
	}
}

func (s *Service) Drain(timeout time.Duration) {
	PerformConcurrently(
		func() {
			if s.active != nil {
				s.active.DrainAll(timeout)
			}
		},
		func() {
			if s.rollout != nil {
				s.rollout.DrainAll(timeout)
			}
		},
	)
}

func (s *Service) loadBalancerForRequest(req *http.Request) *LoadBalancer {
	lb := s.active
	if s.rollout != nil && s.rolloutController != nil && s.rolloutController.RequestUsesRolloutGroup(req) {
		slog.Debug("Using rollout for request", "service", s.name, "path", req.URL.Path)
		lb = s.rollout
	}

	return lb
}

func (s *Service) servesRootPath() bool {
	return slices.Contains(s.options.PathPrefixes, rootPath)
}

func (s *Service) createCertManager(options ServiceOptions) (CertManager, error) {
	if !options.TLSEnabled {
		return nil, nil
	}

	if options.TLSCertificatePath != "" && options.TLSPrivateKeyPath != "" {
		return NewStaticCertManager(options.TLSCertificatePath, options.TLSPrivateKeyPath)
	}

	// Ensure we're not trying to use Let's Encrypt to fetch a wildcard domain,
	// as that is not supported with the challenge types that we use.
	for _, host := range options.Hosts {
		if strings.Contains(host, "*") {
			return nil, ErrorAutomaticTLSDoesNotSupportWildcards
		}
	}

	// Use the shared SAN certificate manager when available. An explicit
	// on-demand URL is a per-service opt-in, so it wins over the shared manager.
	if s.sanCertManager != nil && options.TLSOnDemandURL == "" {
		for _, host := range options.Hosts {
			if host == "" {
				// Catch-all marker, not a provisionable domain
				continue
			}
			if err := s.sanCertManager.RegisterDomain(host, s.name); err != nil {
				slog.Warn("Failed to register domain with SAN cert manager", "host", host, "error", err)
			}
		}
		return s.sanCertManager, nil
	}

	if options.TLSDomainsSource != "" && s.sanCertManager == nil {
		slog.Warn("tls-domains-source requires the proxy to run with --acme-email; dynamic domains will not receive certificates",
			"service", s.name)
	}

	certCache := autocert.DirCache(options.ScopedCachePath())

	hostPolicy, err := s.createHostPolicy(options, certCache)
	if err != nil {
		return nil, err
	}

	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      certCache,
		HostPolicy: hostPolicy,
		Client:     &acme.Client{DirectoryURL: options.ACMEDirectory},
	}, nil
}

func (s *Service) createClientCAs(options ServiceOptions) (*x509.CertPool, error) {
	if options.TLSClientCACertificatePath == "" {
		return nil, nil
	}

	return loadClientCAs(options.TLSClientCACertificatePath)
}

func (s *Service) createHostPolicy(options ServiceOptions, certCache autocert.Cache) (autocert.HostPolicy, error) {
	if options.TLSOnDemandURL != "" {
		checker, err := newTLSOnDemandChecker(s, options.TLSOnDemandURL, certCache)
		if err != nil {
			return nil, err
		}
		return checker.hostPolicy(), nil
	}

	return autocert.HostWhitelist(options.Hosts...), nil
}

func (s *Service) createMiddleware(options ServiceOptions, targetOptions TargetOptions, certManager CertManager) (http.Handler, error) {
	var err error
	var handler http.Handler = http.HandlerFunc(s.serviceRequestWithTarget)

	// Innermost, so that the deadline covers pause waits and target selection as
	// well as the proxied request, while its timeout response still renders
	// through the custom error pages below.
	if targetOptions.RequestTimeout > 0 || len(targetOptions.PathRequestTimeouts) > 0 {
		handler = WithRequestDeadlineMiddleware(targetOptions.RequestTimeout, targetOptions.PathRequestTimeouts, handler)
	}

	// Below the error pages, so that the status the target wrote is rendered by
	// the same templates as one the proxy produced itself.
	if len(options.InterceptErrorStatuses) > 0 {
		handler = WithErrorInterceptMiddleware(options.InterceptErrorStatuses, handler)
	}

	if options.ErrorPagePath != "" {
		slog.Debug("Using custom error pages", "service", s.name, "path", options.ErrorPagePath)
		errorPageFS := os.DirFS(options.ErrorPagePath)
		handler, err = WithErrorPageMiddleware(errorPageFS, false, handler)
		if err != nil {
			slog.Error("Unable to parse custom error pages", "service", s.name, "path", options.ErrorPagePath, "error", err)
			return nil, ErrorUnableToLoadErrorPages
		}
	}

	// Outermost of the middleware that writes a body, so it covers the target's
	// response, the canonical-host redirect, and this service's own error pages.
	// The built-in error pages are rendered by the root middleware above the
	// router (server.go:338), which no per-service option can reach, so those
	// stay uncompressed unless the service sets its own with --error-pages.
	if options.Compression.Enabled() {
		handler = WithCompressionMiddleware(options.Compression, handler)
	}

	// Above compression: an ACME challenge is a handful of bytes served to a
	// certificate authority, and encoding it buys nothing.
	if certManager != nil {
		slog.Debug("Using ACME handler", "service", s.name)
		handler = certManager.HTTPHandler(handler)
	}

	if options.ClientIPHeader != "" {
		handler = WithClientIPMiddleware(options.ClientIPHeader, handler)
	}

	return handler, nil
}

func (s *Service) serviceRequestWithTarget(w http.ResponseWriter, r *http.Request) {
	LoggingRequestContext(r).Service = s.name

	if s.rejectDisallowedIP(w, r) {
		return
	}

	if !s.options.TLSEnabled && r.TLS != nil {
		SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
		return
	}

	if s.handleRedirectsIfNeeded(w, r) {
		return
	}

	// After the redirect, so a 301 -- which never reaches the upstream -- does
	// not spend a token. Before the basic auth challenge, so a password-guessing
	// flood is limited rather than answered indefinitely.
	if s.rejectRateLimited(w, r) {
		return
	}

	// After the redirect, so credentials are never solicited over plaintext on a
	// service that redirects to HTTPS. Before the pause check, so protection
	// does not lapse while a service is paused or stopped.
	if s.rejectUnauthenticated(w, r) {
		return
	}

	if s.handlePausedAndStoppedRequests(w, r) {
		return
	}

	// Last, so that everything above -- the health check exemptions, the
	// redirects, the allow list -- still sees the path the client asked for.
	r = s.rewriteRequest(r)

	// Below every check above, which is what makes a stored response safe: a
	// cache hit is only ever handed to a client the target itself would have
	// been asked on behalf of. Without a cache configured this is the load
	// balancer directly.
	s.cacheHandler.ServeHTTP(w, r)
}

func (s *Service) startLoadBalancerRequest(w http.ResponseWriter, r *http.Request) func() {
	s.serviceLock.RLock()
	defer s.serviceLock.RUnlock()

	lb := s.loadBalancerForRequest(r)
	return lb.StartRequest(w, r)
}

func (s *Service) handlePausedAndStoppedRequests(w http.ResponseWriter, r *http.Request) bool {
	if s.pauseController.GetState() != PauseStateRunning && s.targetOptions.IsHealthCheckRequest(r) {
		// When paused or stopped, return success for any health check
		// requests from downstream services. Otherwise, they might consider
		// us as unhealthy while in that state, and remove us from their
		// pool.
		w.WriteHeader(http.StatusOK)
		return true
	}

	action, message := s.pauseController.Wait()
	switch action {
	case PauseWaitActionStopped:
		templateArguments := struct{ Message string }{message}
		SetErrorResponse(w, r, http.StatusServiceUnavailable, templateArguments)
		return true

	case PauseWaitActionTimedOut:
		slog.Warn("Rejecting request due to expired pause", "service", s.name, "path", r.URL.Path)
		SetErrorResponse(w, r, http.StatusGatewayTimeout, nil)
		return true
	}

	return false
}

func (s *Service) handleRedirectsIfNeeded(w http.ResponseWriter, r *http.Request) bool {
	if url, status := s.redirectURLIfNeeded(r); url != "" {
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, url, status)
		return true
	}
	return false
}

// redirectURLIfNeeded returns a full absolute URL to redirect to, and the status
// to answer with, when TLS redirection, canonical host redirection or a
// redirect rule should occur. If no redirect is needed, it returns an empty
// string.
func (s *Service) redirectURLIfNeeded(r *http.Request) (string, int) {
	if isInternalRequest(r) {
		return "", 0
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	currentScheme := "http"
	if r.TLS != nil {
		currentScheme = "https"
	}

	desiredScheme := currentScheme
	if s.options.TLSEnabled && s.options.TLSRedirect && currentScheme == "http" {
		desiredScheme = "https"
	}

	desiredHost := host
	if s.options.CanonicalHost != "" && host != s.options.CanonicalHost {
		desiredHost = s.options.CanonicalHost
	}

	current := url.URL{Scheme: currentScheme, Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	if location, status := s.redirectRuleURL(current, url.URL{Scheme: desiredScheme, Host: desiredHost}); location != "" {
		return location, status
	}

	if desiredScheme != currentScheme || desiredHost != host {
		return desiredScheme + "://" + desiredHost + r.URL.RequestURI(), http.StatusMovedPermanently
	}

	return "", 0
}
