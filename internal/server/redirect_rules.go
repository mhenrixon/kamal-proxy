package server

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Redirect and rewrite rules move a path without the app knowing about it. A
// redirect answers the client with a Location; a rewrite changes the path the
// target receives while the client's URL stays as it was, which is what an SPA
// serving its own routes from /index.html needs.
//
// Both match the path the client asked for -- before --path-prefix stripping --
// against a regular expression anchored to the whole path, so a rule only fires
// on the path it names rather than on anything containing it.

type pathRuleKind string

const (
	redirectPathRuleKind pathRuleKind = "redirect"
	rewritePathRuleKind  pathRuleKind = "rewrite"
)

var redirectStatuses = []int{
	http.StatusMovedPermanently,
	http.StatusFound,
	http.StatusSeeOther,
	http.StatusTemporaryRedirect,
	http.StatusPermanentRedirect,
}

// PathRule is one pattern and the path or URL a match becomes. Status is only
// meaningful for redirects, where zero means a permanent one.
type PathRule struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
	Status      int    `json:"status,omitempty"`
}

// NewRedirectRules parses the rules that answer a matching request with a
// redirect instead of forwarding it.
func NewRedirectRules(values []string) ([]PathRule, error) {
	return newPathRules(values, redirectPathRuleKind)
}

// NewRewriteRules parses the rules that change the path a matching request
// carries to the target.
func NewRewriteRules(values []string) ([]PathRule, error) {
	return newPathRules(values, rewritePathRuleKind)
}

func (so ServiceOptions) validatePathRules() error {
	for _, rule := range so.Redirects {
		if err := rule.validate(redirectPathRuleKind); err != nil {
			return err
		}
	}

	for _, rule := range so.Rewrites {
		if err := rule.validate(rewritePathRuleKind); err != nil {
			return err
		}
	}

	return nil
}

// Private

// resolvePathRules compiles the stored rules for serving. Unlike the rate limit
// and the IP allow list, a failure here is returned rather than degraded: the
// rules were compiled once already at deploy time, so an unreadable one means
// the state file was edited by hand, and quietly serving the app at a path that
// is supposed to redirect is worse than refusing to start.
func (s *Service) resolvePathRules(options ServiceOptions) (*pathRuleSet, *pathRuleSet, error) {
	redirects, err := newPathRuleSet(options.Redirects, redirectPathRuleKind)
	if err != nil {
		return nil, nil, err
	}

	rewrites, err := newPathRuleSet(options.Rewrites, rewritePathRuleKind)
	if err != nil {
		return nil, nil, err
	}

	return redirects, rewrites, nil
}

// redirectRuleURL resolves the first rule matching the current request into the
// URL to answer with, and the status to answer it with. A rule naming a path is
// completed with the scheme and host the request was headed for anyway, so
// moving a path on a service that also redirects to HTTPS costs the client one
// hop rather than two. Building it that way is also what keeps a captured
// "//evil.example.com" a path on this host rather than a scheme-relative URL
// pointing somewhere else.
func (s *Service) redirectRuleURL(current, desired url.URL) (string, int) {
	match, ok := s.redirects.match(current.Path, current.RawQuery)
	if !ok {
		return "", 0
	}

	if !match.target.IsAbs() {
		match.target.Scheme = desired.Scheme
		match.target.Host = desired.Host
	}

	// A rule that resolves to the request's own URL is dropped rather than
	// answered: the client would follow it around forever.
	location := match.target.String()
	if location == current.String() {
		return "", 0
	}

	return location, match.status
}

// rewriteRequest returns the request the target should see, with the first
// matching rewrite rule applied to its path. The original is returned untouched
// when nothing matches, so a request no rule names allocates nothing.
func (s *Service) rewriteRequest(r *http.Request) *http.Request {
	// The TLS on-demand probe runs through this same chain and asks the backend
	// about one specific path. A catch-all rewrite would point it at the app's
	// index instead, whose 200 would approve a certificate for any host asked
	// for.
	if isInternalRequest(r) {
		return r
	}

	match, ok := s.rewrites.match(r.URL.Path, r.URL.RawQuery)
	if !ok {
		return r
	}

	// A shallow copy, as http.StripPrefix makes: the request is shared with the
	// middleware above, which logs and meters the path the client asked for.
	rewritten := *r
	rewrittenURL := *r.URL
	rewrittenURL.Path = match.target.Path
	rewrittenURL.RawPath = ""
	rewrittenURL.RawQuery = match.target.RawQuery
	rewritten.URL = &rewrittenURL

	return &rewritten
}

// pathRuleSet is the compiled, ready-to-serve form of a service's rules. A nil
// set matches nothing, so a service without rules costs one nil check.
type pathRuleSet struct {
	rules []compiledPathRule
}

type compiledPathRule struct {
	pattern     *regexp.Regexp
	replacement string
	status      int
}

// pathRuleMatch is what a matching rule resolved to. The target carries a path
// and query only, unless the rule named a full URL.
type pathRuleMatch struct {
	target *url.URL
	status int
}

func newPathRuleSet(rules []PathRule, kind pathRuleKind) (*pathRuleSet, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	compiled := make([]compiledPathRule, 0, len(rules))
	for _, rule := range rules {
		pattern, err := compilePathRulePattern(rule, kind)
		if err != nil {
			return nil, err
		}

		compiled = append(compiled, compiledPathRule{
			pattern:     pattern,
			replacement: rule.Replacement,
			status:      rule.Status,
		})
	}

	return &pathRuleSet{rules: compiled}, nil
}

// match returns what the first rule matching path resolves to. The request's
// own query rides along unless the replacement carries one of its own, so that
// moving a path does not silently drop the parameters on it.
func (prs *pathRuleSet) match(path, rawQuery string) (pathRuleMatch, bool) {
	if prs == nil {
		return pathRuleMatch{}, false
	}

	for _, rule := range prs.rules {
		indexes := rule.pattern.FindStringSubmatchIndex(path)
		if indexes == nil {
			continue
		}

		target := splitRuleTarget(string(rule.pattern.ExpandString(nil, rule.replacement, path, indexes)))
		if target.RawQuery == "" {
			target.RawQuery = rawQuery
		}

		status := rule.status
		if status == 0 {
			status = http.StatusMovedPermanently
		}

		return pathRuleMatch{target: target, status: status}, true
	}

	return pathRuleMatch{}, false
}

// splitRuleTarget breaks an expanded replacement into its parts by hand rather
// than through url.Parse. The path it was built from is already decoded, so
// parsing would decode a second time -- and would fail outright on a path
// carrying a literal percent sign.
func splitRuleTarget(value string) *url.URL {
	target := &url.URL{}

	if hasURLScheme(value) {
		var rest string
		target.Scheme, rest, _ = strings.Cut(value, "://")

		var path string
		var rooted bool
		target.Host, path, rooted = strings.Cut(rest, "/")
		if rooted {
			path = "/" + path
		}
		value = path
	}

	target.Path, target.RawQuery, _ = strings.Cut(value, "?")

	return target
}

func newPathRules(values []string, kind pathRuleKind) ([]PathRule, error) {
	if len(values) == 0 {
		return nil, nil
	}

	rules := make([]PathRule, 0, len(values))
	for _, value := range values {
		rule, err := parsePathRule(value, kind)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func parsePathRule(value string, kind pathRuleKind) (PathRule, error) {
	pattern, replacement, found := strings.Cut(value, "=")
	if !found {
		return PathRule{}, fmt.Errorf(`%w: %s must be given as "<pattern>=<replacement>", got %q`,
			ErrServiceOptionsInvalid, kind, value)
	}

	replacement, status := cutRuleStatus(replacement)

	rule := PathRule{Pattern: pattern, Replacement: replacement, Status: status}
	if err := rule.validate(kind); err != nil {
		return PathRule{}, err
	}

	return rule, nil
}

// cutRuleStatus splits a trailing ";status=<code>" off a replacement. Only a
// segment that actually reads as a number is taken, so a replacement carrying a
// semicolon of its own survives intact. Whether the status is allowed at all is
// the caller's business: a rewrite has to report that it cannot carry one,
// rather than silently keeping it as part of the path.
func cutRuleStatus(replacement string) (string, int) {
	head, tail, found := strings.Cut(replacement, ";status=")
	if !found {
		return replacement, 0
	}

	status, err := strconv.Atoi(tail)
	if err != nil {
		return replacement, 0
	}

	return head, status
}

func (rule PathRule) validate(kind pathRuleKind) error {
	if rule.Pattern == "" {
		return fmt.Errorf("%w: %s needs a pattern", ErrServiceOptionsInvalid, kind)
	}

	if rule.Replacement == "" {
		return fmt.Errorf("%w: %s needs a replacement", ErrServiceOptionsInvalid, kind)
	}

	if _, err := compilePathRulePattern(rule, kind); err != nil {
		return err
	}

	if err := rule.validateReplacement(kind); err != nil {
		return err
	}

	if rule.Status != 0 {
		if kind != redirectPathRuleKind {
			return fmt.Errorf("%w: %s cannot set a status", ErrServiceOptionsInvalid, kind)
		}

		if !slices.Contains(redirectStatuses, rule.Status) {
			return fmt.Errorf("%w: redirect status must be one of 301, 302, 303, 307, 308, got %d",
				ErrServiceOptionsInvalid, rule.Status)
		}
	}

	return nil
}

func (rule PathRule) validateReplacement(kind pathRuleKind) error {
	if strings.HasPrefix(rule.Replacement, "/") {
		return nil
	}

	if kind == redirectPathRuleKind && hasURLScheme(rule.Replacement) {
		return nil
	}

	if kind == rewritePathRuleKind {
		return fmt.Errorf("%w: rewrite replacement must be an absolute path, got %q",
			ErrServiceOptionsInvalid, rule.Replacement)
	}

	return fmt.Errorf("%w: redirect replacement must be an absolute path or a full URL, got %q",
		ErrServiceOptionsInvalid, rule.Replacement)
}

// compilePathRulePattern anchors the pattern to the whole path. Without it,
// "/old" would also fire on "/not-old-either", which is never what a rule
// naming a path means.
func compilePathRulePattern(rule PathRule, kind pathRuleKind) (*regexp.Regexp, error) {
	pattern, err := regexp.Compile("^(?:" + rule.Pattern + ")$")
	if err != nil {
		return nil, fmt.Errorf("%w: %s has an invalid pattern %q: %w",
			ErrServiceOptionsInvalid, kind, rule.Pattern, err)
	}

	return pattern, nil
}

func hasURLScheme(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}
