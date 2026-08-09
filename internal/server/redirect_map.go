package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

// Paths the map must never shadow: ACME challenges validate issuance, and the
// proxy's own endpoints (ping, preflight, refresh nudges) must stay reachable
// on every host.
var redirectExemptPrefixes = []string{
	"/.well-known/acme-challenge/",
	"/.kamal-proxy/",
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
// payload-level limits. An empty document is an error on purpose: a tenant
// platform's redirects must never be wiped by a half-deployed app answering
// with nothing; the last good map keeps serving instead.
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

	if len(payload.Hosts) == 0 {
		return nil, fmt.Errorf("redirect list has no hosts; keeping the previous map")
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
}

// dynamicRedirectMap is the compiled, immutable form of one payload. It is
// swapped into the service atomically, so matching never takes a lock.
type dynamicRedirectMap struct {
	hosts     map[string]*compiledHostRedirect
	ruleCount int
}

// compileRedirectMap validates and compiles a payload's host entries. Invalid
// entries are skipped with a warning rather than failing the payload: one
// tenant's broken regex must not stall every other tenant's redirects.
func compileRedirectMap(hosts map[string]redirectHostConfig) *dynamicRedirectMap {
	m := &dynamicRedirectMap{hosts: make(map[string]*compiledHostRedirect, len(hosts))}

	for host, config := range hosts {
		normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if !validDynamicDomain(normalized) {
			slog.Warn("Skipping invalid host in redirects source", "host", host)
			continue
		}

		entry, rules, err := compileHostRedirect(config)
		if err != nil {
			slog.Warn("Skipping invalid host entry in redirects source", "host", host, "error", err)
			continue
		}
		if entry == nil {
			slog.Warn("Skipping empty host entry in redirects source", "host", host)
			continue
		}

		m.hosts[normalized] = entry
		m.ruleCount += rules
	}

	return m
}

// compileHostRedirect compiles one host's entry, returning how many path
// rules survived. A nil entry with a nil error is a no-op entry.
func compileHostRedirect(config redirectHostConfig) (*compiledHostRedirect, int, error) {
	entry := &compiledHostRedirect{status: config.Status, preservePath: config.PreservePath}

	if config.RedirectTo != "" {
		target, err := url.Parse(config.RedirectTo)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid redirect_to %q: %w", config.RedirectTo, err)
		}
		if (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
			return nil, 0, fmt.Errorf("redirect_to must be an absolute http(s) URL, got %q", config.RedirectTo)
		}
		entry.redirectTo = target
	}

	if entry.status == 0 {
		entry.status = http.StatusMovedPermanently
	} else if !slices.Contains(redirectStatuses, entry.status) {
		return nil, 0, fmt.Errorf("redirect status must be one of 301, 302, 303, 307, 308, got %d", entry.status)
	}

	switch config.TrailingSlash {
	case trailingSlashKeep:
	case trailingSlashStrip:
		entry.stripTrailingSlash = true
	default:
		return nil, 0, fmt.Errorf("unknown trailing_slash policy %q", config.TrailingSlash)
	}

	// Path rules share the static rules' grammar and compiler, so a rule means
	// the same thing whichever way it arrived. Invalid rules are dropped
	// individually; the ones before and after still apply in order.
	pathRules := make([]PathRule, 0, len(config.Paths))
	for _, path := range config.Paths {
		rule := PathRule{Pattern: path.From, Replacement: path.To, Status: path.Status}
		if err := rule.validate(redirectPathRuleKind); err != nil {
			slog.Warn("Skipping invalid path rule in redirects source", "from", path.From, "error", err)
			continue
		}
		pathRules = append(pathRules, rule)
	}

	rules, err := newPathRuleSet(pathRules, redirectPathRuleKind)
	if err != nil {
		// validate() above already compiled each pattern; this cannot fail.
		return nil, 0, err
	}
	entry.rules = rules

	if entry.redirectTo == nil && entry.rules == nil && !entry.stripTrailingSlash {
		return nil, 0, nil
	}

	return entry, len(pathRules), nil
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

	for _, prefix := range redirectExemptPrefixes {
		if strings.HasPrefix(current.Path, prefix) {
			return "", 0
		}
	}

	entry := m.hosts[strings.ToLower(current.Host)]
	if entry == nil {
		return "", 0
	}

	if entry.redirectTo != nil {
		target := *entry.redirectTo
		if entry.preservePath {
			target.Path = strings.TrimSuffix(target.Path, "/") + current.Path
			target.RawQuery = current.RawQuery
		}

		// A host redirected to itself would loop forever; drop it rather than
		// answer it, as the static rules do.
		if location := target.String(); location != current.String() {
			return location, entry.status
		}
		return "", 0
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
