package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// The dynamic redirect map is the runtime-editable, host-scoped counterpart of
// the static --redirect rules: the application publishes one JSON document per
// service, the proxy polls it, and a matching request is answered here without
// an app round trip. See dynamic_redirects.go for the polling and persistence;
// this file owns the payload schema, its compiled form, and the matching.

const (
	// maxRedirectListBody caps the decoded payload; the caps sit well above the
	// domains poller's because a tenant platform imports path redirects by the
	// thousand.
	maxRedirectListBody = 10 * MB

	// maxRedirectHosts and maxRedirectPathRules bound the compiled map.
	maxRedirectHosts     = 100000
	maxRedirectPathRules = 100000
)

const (
	trailingSlashKeep  = ""
	trailingSlashStrip = "strip"
)

// redirectExemptPrefixes are paths no redirect rule may shadow: ACME
// challenges validate issuance, and the proxy's own endpoints (ping,
// preflight, refresh nudges) must stay reachable on every host.
var redirectExemptPrefixes = []string{
	"/.well-known/acme-challenge/",
	"/.kamal-proxy/",
}

// isRedirectExemptPath reports whether redirect rules -- dynamic and static
// alike -- must leave this path alone.
func isRedirectExemptPath(path string) bool {
	for _, prefix := range redirectExemptPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// redirectHostConfig is one host's entry in the payload:
//
//	{"hosts": {"old.example": {"redirect_to": "https://www.example", ...}}}
type redirectHostConfig struct {
	// RedirectTo answers every request for this host with a redirect to this
	// URL, before any path rule runs. This is per-host --canonical-host.
	RedirectTo string `json:"redirect_to,omitempty"`
	// Status for RedirectTo; zero means 301.
	Status int `json:"status,omitempty"`
	// PreservePath appends the request's path and query to RedirectTo.
	PreservePath bool `json:"preserve_path,omitempty"`

	// TrailingSlash is a per-host URL policy: "strip" issues a 301 from /foo/
	// to /foo (never for / itself). Empty leaves paths alone.
	TrailingSlash string `json:"trailing_slash,omitempty"`

	// Paths are matched like the static --redirect rules: RE2 anchored to the
	// whole path, $1 expansion, first match wins.
	Paths []redirectPathRule `json:"paths,omitempty"`
}

type redirectPathRule struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status int    `json:"status,omitempty"`
}

// parseRedirectPayload decodes a redirects source payload and enforces the
// payload-level limits. An explicit empty map ({"hosts": {}}) is valid and
// clears the service's redirects; a document with no "hosts" key at all is an
// error, so a half-deployed app answering with the wrong document can never
// wipe live redirects.
func parseRedirectPayload(r io.Reader) (map[string]redirectHostConfig, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRedirectListBody+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read redirect list: %w", err)
	}
	if int64(len(data)) > maxRedirectListBody {
		return nil, fmt.Errorf("redirect list too large (over %d bytes)", maxRedirectListBody)
	}

	var payload struct {
		Hosts map[string]redirectHostConfig `json:"hosts"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse redirect list: %w", err)
	}

	if payload.Hosts == nil {
		return nil, fmt.Errorf("redirect list has no hosts key; keeping the previous map")
	}
	if len(payload.Hosts) > maxRedirectHosts {
		return nil, fmt.Errorf("too many redirect hosts (%d, max %d)", len(payload.Hosts), maxRedirectHosts)
	}

	rules := 0
	for _, host := range payload.Hosts {
		rules += len(host.Paths)
	}
	if rules > maxRedirectPathRules {
		return nil, fmt.Errorf("too many redirect rules (%d, max %d)", rules, maxRedirectPathRules)
	}

	return payload.Hosts, nil
}

// compiledHostRedirect is one host's ready-to-serve entry.
type compiledHostRedirect struct {
	redirectTo         *url.URL
	status             int
	preservePath       bool
	stripTrailingSlash bool
	rules              *pathRuleSet
	ruleCount          int
}

// dynamicRedirectMap is the compiled, immutable form of one payload. It is
// swapped into the service atomically, so matching never takes a lock.
type dynamicRedirectMap struct {
	hosts     map[string]*compiledHostRedirect
	ruleCount int
}

// normalizeRedirectHost is applied to host keys at compile time and to the
// request's host at lookup time, so "Old.Example.COM." in either place still
// meets its entry.
func normalizeRedirectHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// compileRedirectMap validates and compiles a payload's host entries. Invalid
// entries are skipped with a warning rather than failing the payload: one
// tenant's broken regex must not stall every other tenant's redirects. Keys
// are walked in sorted order so a normalization collision resolves the same
// way on every proxy in a fleet.
func compileRedirectMap(hosts map[string]redirectHostConfig) *dynamicRedirectMap {
	m := &dynamicRedirectMap{hosts: make(map[string]*compiledHostRedirect, len(hosts))}

	for _, host := range slices.Sorted(maps.Keys(hosts)) {
		normalized := normalizeRedirectHost(host)
		if !validDynamicDomain(normalized) {
			slog.Warn("Skipping invalid host in redirects source", "host", host)
			continue
		}
		if _, exists := m.hosts[normalized]; exists {
			slog.Warn("Skipping duplicate host in redirects source", "host", host)
			continue
		}

		entry, err := compileHostRedirect(hosts[host])
		if err != nil {
			slog.Warn("Skipping invalid host entry in redirects source", "host", host, "error", err)
			continue
		}
		if entry == nil {
			slog.Warn("Skipping empty host entry in redirects source", "host", host)
			continue
		}

		m.hosts[normalized] = entry
		m.ruleCount += entry.ruleCount
	}

	return m
}

// compileHostRedirect compiles one host's entry. A nil entry with a nil error
// is a no-op entry.
func compileHostRedirect(config redirectHostConfig) (*compiledHostRedirect, error) {
	entry := &compiledHostRedirect{status: config.Status, preservePath: config.PreservePath}

	if config.RedirectTo != "" {
		target, err := url.Parse(config.RedirectTo)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect_to %q: %w", config.RedirectTo, err)
		}
		// Hostname rather than Host: "http://:8080" carries a non-empty
		// authority with no host in it.
		if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" {
			return nil, fmt.Errorf("redirect_to must be an absolute http(s) URL, got %q", config.RedirectTo)
		}
		entry.redirectTo = target
	}

	if entry.status == 0 {
		entry.status = http.StatusMovedPermanently
	} else if !slices.Contains(redirectStatuses, entry.status) {
		return nil, fmt.Errorf("redirect status must be one of 301, 302, 303, 307, 308, got %d", entry.status)
	}

	switch config.TrailingSlash {
	case trailingSlashKeep:
	case trailingSlashStrip:
		entry.stripTrailingSlash = true
	default:
		return nil, fmt.Errorf("unknown trailing_slash policy %q", config.TrailingSlash)
	}

	// Path rules share the static rules' grammar, statuses, and anchoring, so
	// a rule means the same thing whichever way it arrived. Each pattern is
	// compiled exactly once -- with 100k-rule payloads a validate-then-compile
	// double pass is real load time. Invalid rules are dropped individually;
	// the ones before and after still apply in order.
	compiled := make([]compiledPathRule, 0, len(config.Paths))
	for _, path := range config.Paths {
		rule := PathRule{Pattern: path.From, Replacement: path.To, Status: path.Status}

		pattern, err := compilePathRulePattern(rule, redirectPathRuleKind)
		if err != nil {
			slog.Warn("Skipping invalid path rule in redirects source", "from", path.From, "error", err)
			continue
		}
		if err := rule.validateReplacement(redirectPathRuleKind); err != nil {
			slog.Warn("Skipping invalid path rule in redirects source", "from", path.From, "error", err)
			continue
		}
		if rule.Status != 0 && !slices.Contains(redirectStatuses, rule.Status) {
			slog.Warn("Skipping invalid path rule in redirects source", "from", path.From, "status", rule.Status)
			continue
		}

		compiled = append(compiled, compiledPathRule{
			pattern:     pattern,
			replacement: rule.Replacement,
			status:      rule.Status,
		})
	}
	if len(compiled) > 0 {
		entry.rules = &pathRuleSet{rules: compiled}
		entry.ruleCount = len(compiled)
	}

	if entry.redirectTo == nil && entry.rules == nil && !entry.stripTrailingSlash {
		return nil, nil
	}

	return entry, nil
}

// counts reports the compiled map's size, for status output and metrics.
func (m *dynamicRedirectMap) counts() (hosts, rules int) {
	if m == nil {
		return 0, 0
	}
	return len(m.hosts), m.ruleCount
}

// redirectURL resolves the current request against the map: the host-level
// redirect first, then the host's path rules, then its trailing-slash policy.
// A relative target is completed with the desired scheme and host, so a
// dynamic redirect folds into the same hop as the TLS/canonical one.
func (m *dynamicRedirectMap) redirectURL(current, desired url.URL) (string, int) {
	if m == nil {
		return "", 0
	}

	entry := m.hosts[normalizeRedirectHost(current.Host)]
	if entry == nil {
		return "", 0
	}

	if entry.redirectTo != nil {
		target := *entry.redirectTo
		if entry.preservePath {
			target.Path = strings.TrimSuffix(target.Path, "/") + current.Path
			// Carry the escaped form too, so an encoded slash (%2F) in the
			// request survives as data rather than becoming a separator.
			target.RawPath = strings.TrimSuffix(entry.redirectTo.EscapedPath(), "/") + current.EscapedPath()
			target.RawQuery = current.RawQuery
		}

		// A host redirected to itself would loop forever; drop it rather than
		// answer it, as the static rules do.
		if sameResource(&target, &current) {
			return "", 0
		}
		return target.String(), entry.status
	}

	if match, ok := entry.rules.match(current.Path, current.RawQuery); ok {
		return resolveRedirectLocation(match, current, desired)
	}

	if entry.stripTrailingSlash && current.Path != rootPath && strings.HasSuffix(current.Path, "/") {
		target := desired
		target.Path = strings.TrimRight(current.Path, "/")
		if target.Path == "" {
			target.Path = rootPath
		}
		target.RawQuery = current.RawQuery
		return target.String(), http.StatusMovedPermanently
	}

	return "", 0
}
