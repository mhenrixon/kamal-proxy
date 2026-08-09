package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

// emptyUserAgentPattern is the one pattern an absent User-Agent matches. Every
// other rule -- including one like `.*` that technically matches the empty
// string -- requires an agent to actually be present: absence is not a crime,
// and half the non-browser HTTP clients in the world send no User-Agent at all.
const emptyUserAgentPattern = "^$"

// denyList refuses requests whose client address or User-Agent matches a rule
// the operator wrote. It is the abuse-blocking counterpart to ipAllowList: an
// allow list is definitionally impossible for a fleet serving the whole
// internet, and a rate limit bounds sustained abuse but cannot express "this
// network gets nothing".
//
// The client address is resolved through the same forwardedResolver as the
// allow list and the rate limiter -- behind a trusted load balancer, denying
// the connecting peer would deny everyone.
type denyList struct {
	forwardedResolver

	prefixes   []netip.Prefix
	userAgents []denyUserAgentRule

	// denyAll refuses every request. It is only set for stored rules that can
	// no longer be read back: a block that silently lapsed would serve the very
	// traffic the operator asked to refuse.
	denyAll bool

	denied *tokenBucket
}

// denyUserAgentRule is one --deny-user-agent pattern, compiled once at deploy.
// The pattern is kept alongside the matcher so an absent User-Agent can be
// tested against the pattern the operator wrote rather than what it matches.
type denyUserAgentRule struct {
	pattern string
	matcher *regexp.Regexp
}

func newDenyList(denyIPs, denyUserAgents, trustedProxies []string, clientIPHeader string) (*denyList, error) {
	prefixes, err := parseIPPrefixes(denyIPs, "deny-ip")
	if err != nil {
		return nil, err
	}

	userAgents, err := parseDenyUserAgents(denyUserAgents)
	if err != nil {
		return nil, err
	}

	resolver, err := newForwardedResolver(trustedProxies, clientIPHeader)
	if err != nil {
		return nil, err
	}

	return &denyList{
		forwardedResolver: resolver,
		prefixes:          prefixes,
		userAgents:        userAgents,
		denied:            newTokenBucket(deniedLogBurst, deniedLogInterval),
	}, nil
}

// deniesAddr reports whether addr matches a deny rule. The zero Addr matches
// nothing: a deny names exactly what the operator wrote, and an unresolvable
// client is not any of those things. (The allow list still refuses the zero
// Addr when one is configured; the two fail in the direction each is for.)
func (l *denyList) deniesAddr(addr netip.Addr) bool {
	return addr.IsValid() && containsAddr(l.prefixes, addr)
}

// deniesUserAgent reports whether the request's User-Agent matches a deny
// rule. Patterns match the full header value, not a substring of it.
func (l *denyList) deniesUserAgent(userAgent string) bool {
	if userAgent == "" {
		for _, rule := range l.userAgents {
			if rule.pattern == emptyUserAgentPattern {
				return true
			}
		}

		return false
	}

	for _, rule := range l.userAgents {
		if rule.matcher.MatchString(userAgent) {
			return true
		}
	}

	return false
}

// Private

func parseDenyUserAgents(patterns []string) ([]denyUserAgentRule, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	rules := make([]denyUserAgentRule, 0, len(patterns))
	for _, pattern := range patterns {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			return nil, fmt.Errorf("%w: deny-user-agent: pattern cannot be empty (use %q to deny requests without a User-Agent)", ErrServiceOptionsInvalid, emptyUserAgentPattern)
		}

		// Anchored to the whole header value: `BadBot/.*` means that agent, not
		// any agent that happens to mention it somewhere.
		matcher, err := regexp.Compile(`\A(?:` + trimmed + `)\z`)
		if err != nil {
			return nil, fmt.Errorf("%w: deny-user-agent: %q is not a valid RE2 pattern", ErrServiceOptionsInvalid, trimmed)
		}

		rules = append(rules, denyUserAgentRule{pattern: trimmed, matcher: matcher})
	}

	return rules, nil
}

func (so ServiceOptions) validateDeny() error {
	if _, err := parseIPPrefixes(so.DenyIPs, "deny-ip"); err != nil {
		return err
	}

	if _, err := parseDenyUserAgents(so.DenyUserAgents); err != nil {
		return err
	}

	// Same trap as allow-ip: without a declared proxy the header is just
	// something the client wrote, so honouring it would appear to consult it
	// while matching the connecting peer instead.
	if len(so.DenyIPs) > 0 && so.ClientIPHeader != "" && len(so.TrustedProxies) == 0 {
		return fmt.Errorf("%w: deny-ip with client-ip-header requires trusted-proxy, or the header would be ignored while appearing to be honored", ErrServiceOptionsInvalid)
	}

	return nil
}

// hasDenyRules reports whether any deny rule is configured, of either kind.
func (so ServiceOptions) hasDenyRules() bool {
	return len(so.DenyIPs) > 0 || len(so.DenyUserAgents) > 0
}

// validateDenyHealthCheck rejects the health check path that would quietly
// unblock the service, matching the equivalent rule for basic auth, allow-ip
// and rate-limit.
func validateDenyHealthCheck(options ServiceOptions, targetOptions TargetOptions) error {
	if !options.hasDenyRules() {
		return nil
	}

	path := targetOptions.HealthCheckConfig.Path
	if path == "" || path == rootPath {
		return fmt.Errorf("%w: health-check-path cannot be %q when deny rules are set, as that path is served without them", ErrServiceOptionsInvalid, rootPath)
	}

	return nil
}

// resolveDenyList prepares the stored rules for serving. It never returns an
// error: this runs from initialize, which runs while decoding saved state, and
// failing there would abort the decode of every other service too.
func (s *Service) resolveDenyList(options ServiceOptions) *denyList {
	if !options.hasDenyRules() {
		return nil
	}

	list, err := newDenyList(options.DenyIPs, options.DenyUserAgents, options.TrustedProxies, options.ClientIPHeader)
	if err != nil {
		slog.Error("Unable to read the stored deny rules; denying every request to this service", "service", s.name, "error", err)

		return &denyList{denyAll: true, denied: newTokenBucket(deniedLogBurst, deniedLogInterval)}
	}

	slog.Info("Deny rules enabled", "service", s.name, "deny_ips", options.DenyIPs,
		"deny_user_agents", options.DenyUserAgents, "trusted_proxies", options.TrustedProxies)

	return list
}

// rejectDenied refuses a request matching this service's deny rules, reporting
// whether it handled the response.
//
// It runs as the very first check in serviceRequestWithTarget -- before the
// allow list, so an address on both lists is denied; before the TLS redirect,
// because a 403 solicits nothing; before the rate limit, so a denied client
// never spends budget; and before basic auth, so a denied network never learns
// credentials are wanted. It deliberately does NOT live in createMiddleware --
// that chain includes the certificate manager's handler, so filtering up there
// would block ACME HTTP-01 validation and break renewal weeks later.
func (s *Service) rejectDenied(w http.ResponseWriter, r *http.Request) bool {
	if s.denyRules == nil {
		return false
	}

	// Probes the proxy makes about itself, and health checks a downstream load
	// balancer needs in order to see this service drain during a deploy.
	if isInternalRequest(r) || s.targetOptions.IsHealthCheckRequest(r) {
		return false
	}

	kind := ""
	switch {
	case s.denyRules.denyAll:
		kind = "unreadable"
	case s.denyRules.deniesAddr(s.denyRules.clientAddr(r)):
		// The address checks run before the User-Agent ones: cheapest first.
		kind = "ip"
	case s.denyRules.deniesUserAgent(r.Header.Get("User-Agent")):
		kind = "user_agent"
	default:
		return false
	}

	s.logDenied(r, kind)
	metrics.Tracker.TrackDenial(s.name, kind)

	// A 403 through the error-page machinery, echoing nothing about the rule.
	SetErrorResponse(w, r, http.StatusForbidden, nil)

	return true
}

func (s *Service) logDenied(r *http.Request, kind string) {
	if !s.denyRules.denied.TryTake() {
		return
	}

	slog.Warn("Denied by deny rules", "service", s.name, "rule", kind, "peer", r.RemoteAddr, "path", r.URL.Path)
}
