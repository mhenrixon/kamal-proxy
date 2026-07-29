package server

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// rateLimitIPv6PrefixBits is the granularity IPv6 clients are counted at.
	//
	// Keying on the full /128 address would make the limit decorative: every
	// IPv6 client holds at least a /64 and can pick a fresh source address per
	// request, which both escapes the budget and allocates a bucket each time.
	// A /64 is the smallest allocation guaranteed to be a single subnet, so
	// grouping at it never charges one customer for another's traffic.
	rateLimitIPv6PrefixBits = 64

	// rateLimitMaxTrackedClients bounds the bucket map, which is otherwise a
	// memory-exhaustion primitive handed to anyone who can vary a source
	// address. Clients past the cap share the overflow bucket -- still limited,
	// just not individually.
	rateLimitMaxTrackedClients = 50_000

	// How often idle buckets are swept out. Sweeping is lazy rather than run
	// from a goroutine, so a redeploy cannot leak one.
	rateLimitSweepInterval = time.Minute

	// Throttled requests are logged at most this often per service.
	rateLimitLogBurst    = 10
	rateLimitLogInterval = 10 * time.Second
)

// rateLimiter is a per-client token bucket set.
//
// The client is resolved through the same forwardedResolver the allow list
// uses. That matters more here than it looks: behind a load balancer every
// request carries the balancer's address, so keying on the connecting peer
// would put the entire internet in one bucket and the first burst would lock
// everyone out. Headers are still only consulted when the peer is a declared
// trusted proxy -- otherwise a client picks its own bucket and the limit is
// free to escape.
type rateLimiter struct {
	forwardedResolver

	limit  rate.Limit
	burst  int
	exempt []netip.Prefix

	mu        sync.Mutex
	buckets   map[netip.Prefix]*rate.Limiter
	overflow  *rate.Limiter
	lastSweep time.Time

	now       func() time.Time
	throttled *tokenBucket
}

func newRateLimiter(limit float64, burst int, exempt, trustedProxies []string, clientIPHeader string) (*rateLimiter, error) {
	exemptPrefixes, err := parseIPPrefixes(exempt, "rate-limit-exempt")
	if err != nil {
		return nil, err
	}

	resolver, err := newForwardedResolver(trustedProxies, clientIPHeader)
	if err != nil {
		return nil, err
	}

	limiter := newBareRateLimiter(limit, burst)
	limiter.exempt = exemptPrefixes
	limiter.forwardedResolver = resolver

	return limiter, nil
}

// newBareRateLimiter builds a limiter that exempts nobody and trusts no proxy.
// It is the fallback for stored settings that cannot be read back.
func newBareRateLimiter(limit float64, burst int) *rateLimiter {
	if burst <= 0 {
		burst = max(1, int(math.Ceil(limit)))
	}

	now := time.Now()

	return &rateLimiter{
		limit:     rate.Limit(limit),
		burst:     burst,
		buckets:   make(map[netip.Prefix]*rate.Limiter),
		overflow:  rate.NewLimiter(rate.Limit(limit), burst),
		lastSweep: now,
		now:       time.Now,
		throttled: newTokenBucket(rateLimitLogBurst, rateLimitLogInterval),
	}
}

// allow reports whether this request is within its client's budget, spending a
// token when it is.
func (l *rateLimiter) allow(r *http.Request) bool {
	addr := l.clientAddr(r)

	if addr.IsValid() && containsAddr(l.exempt, addr) {
		return true
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepIfDue(now)

	return l.bucketFor(addr).AllowN(now, 1)
}

// retryAfterSeconds is how long a throttled client should wait for its next
// token, as the whole seconds RFC 9110 requires of Retry-After.
func (l *rateLimiter) retryAfterSeconds() int {
	return max(1, int(math.Ceil(1/float64(l.limit))))
}

// tracked is the number of individually counted clients.
func (l *rateLimiter) tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.buckets)
}

// Private

// bucketFor returns the bucket this client spends from. Callers hold l.mu.
//
// The zero Addr -- an unparseable peer, or a forwarded chain we could not
// resolve -- shares the overflow bucket rather than being waved through or
// refused outright: waving through makes a malformed chain an escape hatch,
// and refusing would hard-fail any transport without an IP peer.
func (l *rateLimiter) bucketFor(addr netip.Addr) *rate.Limiter {
	if !addr.IsValid() {
		return l.overflow
	}

	key := rateLimitClientKey(addr)
	if bucket, ok := l.buckets[key]; ok {
		return bucket
	}

	// At the cap, new clients share the overflow bucket. Leaving them untracked
	// would mean unlimited, which is the escape this feature exists to close.
	if len(l.buckets) >= rateLimitMaxTrackedClients {
		return l.overflow
	}

	bucket := rate.NewLimiter(l.limit, l.burst)
	l.buckets[key] = bucket

	return bucket
}

// sweepIfDue drops buckets that have refilled completely. Callers hold l.mu.
//
// A full bucket is indistinguishable from one that has never been used, so
// forgetting it changes no decision. A bucket still in debt is kept: evicting
// that one would hand back a budget the client has already spent, which is
// exactly the amnesty a rotating attacker wants.
func (l *rateLimiter) sweepIfDue(now time.Time) {
	if now.Sub(l.lastSweep) < rateLimitSweepInterval {
		return
	}
	l.lastSweep = now

	full := float64(l.burst)
	for key, bucket := range l.buckets {
		if bucket.TokensAt(now) >= full {
			delete(l.buckets, key)
		}
	}
}

// rateLimitClientKey is the identity a budget belongs to: the whole address for
// IPv4, the /64 for IPv6. See rateLimitIPv6PrefixBits.
func rateLimitClientKey(addr netip.Addr) netip.Prefix {
	addr = normalizeAddr(addr)

	if addr.Is6() {
		return netip.PrefixFrom(addr, rateLimitIPv6PrefixBits).Masked()
	}

	return netip.PrefixFrom(addr, addr.BitLen())
}

func (so ServiceOptions) validateRateLimit() error {
	if so.RateLimit < 0 {
		return fmt.Errorf("%w: rate-limit cannot be negative", ErrServiceOptionsInvalid)
	}

	if so.RateLimit == 0 {
		if so.RateLimitBurst != 0 {
			return fmt.Errorf("%w: rate-limit-burst requires rate-limit", ErrServiceOptionsInvalid)
		}
		if len(so.RateLimitExempt) > 0 {
			return fmt.Errorf("%w: rate-limit-exempt requires rate-limit", ErrServiceOptionsInvalid)
		}

		return nil
	}

	if so.RateLimitBurst < 0 {
		return fmt.Errorf("%w: rate-limit-burst cannot be negative", ErrServiceOptionsInvalid)
	}

	// Same trap as allow-ip: without a declared proxy the header is just
	// something the client wrote, so honouring it would let every client pick
	// its own bucket.
	if so.ClientIPHeader != "" && len(so.TrustedProxies) == 0 {
		return fmt.Errorf("%w: rate-limit with client-ip-header requires trusted-proxy, or the header would be ignored while appearing to be honored", ErrServiceOptionsInvalid)
	}

	_, err := parseIPPrefixes(so.RateLimitExempt, "rate-limit-exempt")

	return err
}

// validateRateLimitHealthCheck rejects the health check path that would quietly
// unlimit the service, matching the equivalent rule for basic auth and allow-ip.
func validateRateLimitHealthCheck(options ServiceOptions, targetOptions TargetOptions) error {
	if options.RateLimit <= 0 {
		return nil
	}

	path := targetOptions.HealthCheckConfig.Path
	if path == "" || path == rootPath {
		return fmt.Errorf("%w: health-check-path cannot be %q when rate-limit is set, as that path is served without a rate limit", ErrServiceOptionsInvalid, rootPath)
	}

	return nil
}

// resolveRateLimiter prepares the stored settings for serving. It never returns
// an error: this runs from initialize, which runs while decoding saved state,
// and failing there would abort the decode of every other service too.
func (s *Service) resolveRateLimiter(options ServiceOptions) *rateLimiter {
	if options.RateLimit <= 0 {
		return nil
	}

	limiter, err := newRateLimiter(options.RateLimit, options.RateLimitBurst,
		options.RateLimitExempt, options.TrustedProxies, options.ClientIPHeader)
	if err == nil {
		slog.Info("Rate limiting enabled", "service", s.name, "limit", options.RateLimit,
			"burst", limiter.burst, "exempt", options.RateLimitExempt, "trusted_proxies", options.TrustedProxies)

		return limiter
	}

	// Drop the exemptions and the proxy trust rather than honour half of them:
	// an unreadable exemption must not become an unlimited client, and an
	// unreadable proxy list must not leave a header being trusted.
	slog.Error("Unable to read the stored rate limit settings; counting every client by its connecting address, with no exemptions",
		"service", s.name, "error", err)

	return newBareRateLimiter(options.RateLimit, options.RateLimitBurst)
}

// rejectRateLimited refuses a request whose client is over budget, reporting
// whether it handled the response.
//
// It runs from serviceRequestWithTarget rather than createMiddleware, for the
// same reason as the allow list: that chain includes the certificate manager's
// handler, so limiting up there would throttle ACME HTTP-01 validation and
// break renewal weeks later.
//
// Its position within that handler is load-bearing in both directions. After
// handleRedirectsIfNeeded, because a 301 never reaches the upstream and
// charging it a token would halve the effective limit for every browser
// navigation on a redirecting service. Before rejectUnauthenticated, because
// limiting a password-guessing flood is the main thing this buys a --basic-auth
// service.
func (s *Service) rejectRateLimited(w http.ResponseWriter, r *http.Request) bool {
	if s.rateLimiter == nil {
		return false
	}

	// Probes the proxy makes about itself, and health checks a downstream load
	// balancer needs in order to see this service drain during a deploy. A 429
	// on a probe reads as "down" and turns a rate limit into an outage.
	if isInternalRequest(r) || s.targetOptions.IsHealthCheckRequest(r) {
		return false
	}

	if s.rateLimiter.allow(r) {
		return false
	}

	s.logRateLimited(r)

	w.Header().Set("Retry-After", strconv.Itoa(s.rateLimiter.retryAfterSeconds()))
	SetErrorResponse(w, r, http.StatusTooManyRequests, nil)

	return true
}

func (s *Service) logRateLimited(r *http.Request) {
	if !s.rateLimiter.throttled.TryTake() {
		return
	}

	slog.Warn("Rate limited", "service", s.name, "peer", r.RemoteAddr,
		"client_addr", s.rateLimiter.clientAddr(r).String(), "path", r.URL.Path)
}
