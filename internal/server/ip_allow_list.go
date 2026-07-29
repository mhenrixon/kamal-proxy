package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	// forwardedChainLimit bounds how far back through a forwarded chain we walk,
	// so a long header cannot turn every request into a linear scan.
	forwardedChainLimit = 32

	// Denials are logged at most this often per service. A scanner would
	// otherwise fill the log with one line per probe.
	deniedLogBurst    = 10
	deniedLogInterval = 10 * time.Second
)

// ipAllowList decides whether a request's client address is permitted.
//
// The address it matches is the one net/http wrote into r.RemoteAddr from the
// accepted TCP connection. Nothing in this proxy lets a client influence that
// value, which is what makes the filter meaningful. Every other IP-shaped value
// on a request -- X-Forwarded-For, X-Real-IP, and whatever --client-ip-header
// names -- is written by the client and is only consulted when the peer itself
// is one of the operator's declared proxies.
type ipAllowList struct {
	prefixes       []netip.Prefix
	trusted        []netip.Prefix
	clientIPHeader string

	denied *tokenBucket
}

func newIPAllowList(allowIPs, trustedProxies []string, clientIPHeader string) (*ipAllowList, error) {
	prefixes, err := parseIPPrefixes(allowIPs, "allow-ip")
	if err != nil {
		return nil, err
	}

	trusted, err := parseIPPrefixes(trustedProxies, "trusted-proxy")
	if err != nil {
		return nil, err
	}

	header := ""
	if clientIPHeader != "" {
		header = http.CanonicalHeaderKey(clientIPHeader)
	}

	return &ipAllowList{
		prefixes:       prefixes,
		trusted:        trusted,
		clientIPHeader: header,
		denied:         newTokenBucket(deniedLogBurst, deniedLogInterval),
	}, nil
}

// permits reports whether addr falls inside the allow list. The zero Addr --
// which is what an unparseable peer or an unresolvable forwarded chain produces
// -- is never permitted, not even by a default route.
func (l *ipAllowList) permits(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	return containsAddr(l.prefixes, addr)
}

// clientAddr resolves the address to match this request against.
//
// With no trusted proxies declared, that is always the peer. Otherwise, when
// the peer is one of ours, the client is taken from the forwarded chain by
// walking it from the nearest hop backwards past any other proxy of ours; the
// first address a proxy of ours did not write is the client. An unresolvable
// chain returns the zero Addr, which denies: falling back to the peer would be
// a bypass on the very plausible configuration where the allow list contains
// the proxy's own range.
func (l *ipAllowList) clientAddr(r *http.Request) netip.Addr {
	peer := parseHostAddr(r.RemoteAddr)

	if len(l.trusted) == 0 || !peer.IsValid() || !containsAddr(l.trusted, peer) {
		return peer
	}

	return l.forwardedAddr(r)
}

// forwardedAddr walks the forwarded chain from the nearest hop backwards.
//
// The header is read with Values, not Get: repeated header lines are distinct
// entries, and a hop that appends its own line rather than folding into the
// client's leaves the client's forged line first. Reading only that line would
// hand the whole walk to the attacker.
func (l *ipAllowList) forwardedAddr(r *http.Request) netip.Addr {
	header := "X-Forwarded-For"
	if l.clientIPHeader != "" {
		// ClientIPMiddleware rewrites X-Forwarded-For from this header before we
		// run, so read the original rather than the value it left behind.
		header = l.clientIPHeader
	}

	entries := []string{}
	for _, value := range r.Header.Values(header) {
		entries = append(entries, strings.Split(value, ",")...)
	}

	if len(entries) > forwardedChainLimit {
		entries = entries[len(entries)-forwardedChainLimit:]
	}

	for i := len(entries) - 1; i >= 0; i-- {
		addr := parseForwardedAddr(entries[i])
		if !addr.IsValid() {
			return netip.Addr{}
		}

		if !containsAddr(l.trusted, addr) {
			return addr
		}
	}

	return netip.Addr{}
}

// Private

// normalizeAddr puts an address into the one form the prefixes are compared
// against: IPv4-mapped IPv6 unwrapped to plain IPv4, and any zone dropped.
// Without the unmap, ::ffff:203.0.113.5 does not match 203.0.113.0/24 and the
// list is bypassed by connecting over IPv6.
func normalizeAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = normalizeAddr(addr)

	return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
		return prefix.Contains(addr)
	})
}

// parseHostAddr reads the address out of a "host:port" pair such as
// r.RemoteAddr, returning the zero Addr when it is not one.
func parseHostAddr(hostPort string) netip.Addr {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}
	}

	return normalizeAddr(addr)
}

// parseForwardedAddr reads one entry of a forwarded chain. Entries are normally
// bare addresses, but some proxies append a port.
func parseForwardedAddr(entry string) netip.Addr {
	entry = strings.TrimSpace(entry)

	if addr, err := netip.ParseAddr(entry); err == nil {
		return normalizeAddr(addr)
	}

	return parseHostAddr(entry)
}

func parseIPPrefix(entry string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return netip.Prefix{}, fmt.Errorf("address or CIDR range cannot be empty")
	}

	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR range", entry)
		}
		if prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped range; write it as plain IPv4", entry)
		}

		// Masked so that 10.1.2.3/8 and 10.0.0.0/8 behave identically.
		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid address", entry)
	}
	if addr.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped address; write it as plain IPv4", entry)
	}
	// A zoned address matches nothing, so accepting one would silently do
	// nothing rather than what the operator asked for.
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q carries an IPv6 zone; write the address without it", entry)
	}

	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func parseIPPrefixes(entries []string, flagName string) ([]netip.Prefix, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := parseIPPrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %s", ErrServiceOptionsInvalid, flagName, err)
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func (so ServiceOptions) validateAllowIPs() error {
	if len(so.TrustedProxies) > 0 && len(so.AllowIPs) == 0 {
		return fmt.Errorf("%w: trusted-proxy requires allow-ip", ErrServiceOptionsInvalid)
	}

	if len(so.AllowIPs) > 0 && so.ClientIPHeader != "" && len(so.TrustedProxies) == 0 {
		return fmt.Errorf("%w: allow-ip with client-ip-header requires trusted-proxy, or the header would be ignored while appearing to be honored", ErrServiceOptionsInvalid)
	}

	if _, err := parseIPPrefixes(so.AllowIPs, "allow-ip"); err != nil {
		return err
	}

	trusted, err := parseIPPrefixes(so.TrustedProxies, "trusted-proxy")
	if err != nil {
		return err
	}

	// Trusting everything means trusting every client to speak for someone else,
	// which is the whole bypass this flag exists to prevent.
	for _, prefix := range trusted {
		if prefix.Bits() == 0 {
			return fmt.Errorf("%w: trusted-proxy cannot contain a default route (%s)", ErrServiceOptionsInvalid, prefix)
		}
	}

	return nil
}

// validateAllowIPsHealthCheck rejects the health check path that would quietly
// unrestrict the service, matching the equivalent rule for basic auth.
func validateAllowIPsHealthCheck(options ServiceOptions, targetOptions TargetOptions) error {
	if len(options.AllowIPs) == 0 {
		return nil
	}

	path := targetOptions.HealthCheckConfig.Path
	if path == "" || path == rootPath {
		return fmt.Errorf("%w: health-check-path cannot be %q when allow-ip is set, as that path is served without an address check", ErrServiceOptionsInvalid, rootPath)
	}

	return nil
}

// resolveIPAllowList prepares the stored list for serving. It never returns an
// error: this runs from initialize, which runs while decoding saved state, and
// failing there would abort the decode of every other service too.
func (s *Service) resolveIPAllowList(options ServiceOptions) *ipAllowList {
	if len(options.AllowIPs) == 0 {
		return nil
	}

	list, err := newIPAllowList(options.AllowIPs, options.TrustedProxies, options.ClientIPHeader)
	if err != nil {
		slog.Error("Unable to read the stored allow list; denying every request to this service", "service", s.name, "error", err)

		return &ipAllowList{denied: newTokenBucket(deniedLogBurst, deniedLogInterval)}
	}

	if !slices.ContainsFunc(list.prefixes, func(p netip.Prefix) bool { return p.Addr().Is6() }) {
		slog.Warn("allow-ip lists no IPv6 ranges; clients reaching the proxy over IPv6 will be denied", "service", s.name)
	}
	if len(list.trusted) > 0 && !slices.ContainsFunc(list.trusted, func(p netip.Prefix) bool { return p.Addr().Is6() }) {
		slog.Warn("trusted-proxy lists no IPv6 ranges; requests arriving over IPv6 will be matched on the connecting address instead of the forwarded one", "service", s.name)
	}

	slog.Info("Client address filtering enabled", "service", s.name, "allow", options.AllowIPs, "trusted_proxies", options.TrustedProxies)

	return list
}

// rejectDisallowedIP denies a request whose client address is outside the
// service's allow list, reporting whether it handled the response.
//
// It runs as the first check in serviceRequestWithTarget, before the HTTPS
// redirect: a 403 solicits nothing, so there is no reason to redirect a peer we
// are about to refuse. It deliberately does NOT live in createMiddleware --
// that chain wraps this handler and includes the certificate manager's own
// handler, so filtering up there would block ACME HTTP-01 validation and break
// certificate issuance and renewal weeks later.
func (s *Service) rejectDisallowedIP(w http.ResponseWriter, r *http.Request) bool {
	if s.allowedIPs == nil {
		return false
	}

	// Probes the proxy makes about itself, and health checks a downstream load
	// balancer needs in order to see this service drain during a deploy.
	if isInternalRequest(r) || s.targetOptions.IsHealthCheckRequest(r) {
		return false
	}

	addr := s.allowedIPs.clientAddr(r)
	if s.allowedIPs.permits(addr) {
		return false
	}

	s.logDeniedIP(r, addr)
	SetErrorResponse(w, r, http.StatusForbidden, nil)

	return true
}

func (s *Service) logDeniedIP(r *http.Request, addr netip.Addr) {
	if !s.allowedIPs.denied.TryTake() {
		return
	}

	// The access log records the peer and the client's own header claim, neither
	// of which is necessarily the address this decision used, so say which it
	// was and why it failed.
	reason := "address not allowed"
	resolved := addr.String()
	if !addr.IsValid() {
		reason = "could not determine a client address"
		resolved = ""
	}

	slog.Warn("Denied by allow-ip", "service", s.name, "peer", r.RemoteAddr, "client_addr", resolved, "reason", reason, "path", r.URL.Path)
}

// withMetricsAllowList restricts the metrics endpoint to the given ranges. The
// metrics server is its own listener with no service behind it, so it matches
// the connecting address only -- there is no forwarded chain to trust here.
func withMetricsAllowList(allowed []netip.Prefix, next http.Handler) http.Handler {
	if len(allowed) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := parseHostAddr(r.RemoteAddr)
		if !addr.IsValid() || !containsAddr(allowed, addr) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
