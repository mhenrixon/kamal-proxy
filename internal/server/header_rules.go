package server

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// Header rules let a service set CORS, HSTS, CSP or any other header without
// the app knowing about it. Request rules apply to what the target receives,
// response rules to what the client receives.

type headerDirection string

const (
	requestHeaderDirection  headerDirection = "request"
	responseHeaderDirection headerDirection = "response"
)

// HeaderRule is one header name and the value a rule gives it.
type HeaderRule struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HeaderRules are the header changes applied to one direction of a proxied
// request. They run in field order -- removals, then sets, then adds -- so
// naming the same header under more than one verb resolves the same way no
// matter what order the flags were given in.
type HeaderRules struct {
	Remove []string     `json:"remove,omitempty"`
	Set    []HeaderRule `json:"set,omitempty"`
	Add    []HeaderRule `json:"add,omitempty"`
}

// HeaderRuleFlags are the raw flag values for one direction: sets and adds as
// "<name>: <value>", removals as a bare name.
type HeaderRuleFlags struct {
	Remove []string
	Set    []string
	Add    []string
}

// NewRequestHeaderRules parses the rules applied to requests on their way to
// the target.
func NewRequestHeaderRules(flags HeaderRuleFlags) (HeaderRules, error) {
	return newHeaderRules(flags, requestHeaderDirection)
}

// NewResponseHeaderRules parses the rules applied to responses on their way
// back to the client.
func NewResponseHeaderRules(flags HeaderRuleFlags) (HeaderRules, error) {
	return newHeaderRules(flags, responseHeaderDirection)
}

// Private

// apply mutates header in place. Names arrive canonicalized, and http.Header's
// own methods canonicalize again, so rules restored from a state file written
// by a different version still match.
func (hr HeaderRules) apply(header http.Header) {
	for _, name := range hr.Remove {
		header.Del(name)
	}
	for _, rule := range hr.Set {
		header.Set(rule.Name, rule.Value)
	}
	for _, rule := range hr.Add {
		header.Add(rule.Name, rule.Value)
	}
}

func newHeaderRules(flags HeaderRuleFlags, direction headerDirection) (HeaderRules, error) {
	remove, err := parseHeaderNames(flags.Remove, direction, "remove")
	if err != nil {
		return HeaderRules{}, err
	}

	set, err := parseHeaderRules(flags.Set, direction, "set")
	if err != nil {
		return HeaderRules{}, err
	}

	add, err := parseHeaderRules(flags.Add, direction, "add")
	if err != nil {
		return HeaderRules{}, err
	}

	return HeaderRules{Remove: remove, Set: set, Add: add}, nil
}

func parseHeaderNames(values []string, direction headerDirection, verb string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	names := make([]string, 0, len(values))
	for _, value := range values {
		name, err := parseHeaderName(strings.TrimSpace(value), direction, verb)
		if err != nil {
			return nil, err
		}

		names = append(names, name)
	}

	return names, nil
}

func parseHeaderRules(values []string, direction headerDirection, verb string) ([]HeaderRule, error) {
	if len(values) == 0 {
		return nil, nil
	}

	rules := make([]HeaderRule, 0, len(values))
	for _, value := range values {
		// Cut at the first colon: a value may contain colons of its own, as a CSP
		// naming a scheme or a port does.
		rawName, rawValue, found := strings.Cut(value, ":")
		if !found {
			return nil, fmt.Errorf(`%w: %s must be given as "<name>: <value>", got %q`,
				ErrTargetOptionsInvalid, headerRuleFlagName(direction, verb), value)
		}

		name, err := parseHeaderName(strings.TrimSpace(rawName), direction, verb)
		if err != nil {
			return nil, err
		}

		headerValue := strings.TrimSpace(rawValue)
		if !httpguts.ValidHeaderFieldValue(headerValue) {
			return nil, fmt.Errorf("%w: %s has an invalid value for %s: %q",
				ErrTargetOptionsInvalid, headerRuleFlagName(direction, verb), name, headerValue)
		}

		rules = append(rules, HeaderRule{Name: name, Value: headerValue})
	}

	return rules, nil
}

func parseHeaderName(name string, direction headerDirection, verb string) (string, error) {
	if !httpguts.ValidHeaderFieldName(name) {
		return "", fmt.Errorf("%w: %s has an invalid header name: %q",
			ErrTargetOptionsInvalid, headerRuleFlagName(direction, verb), name)
	}

	canonical := http.CanonicalHeaderKey(name)

	// Go carries the request host in Request.Host rather than the header map, and
	// the transport writes the request line from it while dropping any Host key
	// left in the map. A rule naming it would silently do nothing, so say so.
	if direction == requestHeaderDirection && canonical == "Host" {
		return "", fmt.Errorf("%w: %s cannot rewrite the Host header",
			ErrTargetOptionsInvalid, headerRuleFlagName(direction, verb))
	}

	return canonical, nil
}

func headerRuleFlagName(direction headerDirection, verb string) string {
	return fmt.Sprintf("%s-%s-header", verb, direction)
}
