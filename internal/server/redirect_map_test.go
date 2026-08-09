package server

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRedirectPayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		hosts    int
		errorMsg string
	}{
		{
			name:    "valid payload",
			payload: `{"hosts": {"old.example.com": {"redirect_to": "https://www.example.com", "preserve_path": true}}}`,
			hosts:   1,
		},
		{
			name:    "host rules and trailing slash",
			payload: `{"hosts": {"www.example.com": {"trailing_slash": "strip", "paths": [{"from": "/old", "to": "/new"}]}}}`,
			hosts:   1,
		},
		{
			name:     "invalid JSON",
			payload:  `{"hosts": {`,
			errorMsg: "failed to parse redirect list",
		},
		{
			name:     "empty hosts must not wipe the last good map",
			payload:  `{"hosts": {}}`,
			errorMsg: "no hosts",
		},
		{
			name:     "missing hosts key",
			payload:  `{}`,
			errorMsg: "no hosts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := parseRedirectPayload(strings.NewReader(tt.payload))
			if tt.errorMsg != "" {
				require.ErrorContains(t, err, tt.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.Len(t, hosts, tt.hosts)
		})
	}
}

func TestParseRedirectPayload_RejectsOversizePayload(t *testing.T) {
	payload := `{"hosts": {"a.example.com": {"redirect_to": "https://b.example/` + strings.Repeat("a", int(maxRedirectListBody)) + `"}}}`
	_, err := parseRedirectPayload(strings.NewReader(payload))
	require.ErrorContains(t, err, "redirect list too large")
}

func TestParseRedirectPayload_RejectsTooManyRules(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"hosts": {"a.example.com": {"paths": [`)
	for i := 0; i <= maxRedirectPathRules; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"from": "/a%d", "to": "/b"}`, i)
	}
	sb.WriteString(`]}}}`)

	_, err := parseRedirectPayload(strings.NewReader(sb.String()))
	require.ErrorContains(t, err, "too many redirect rules")
}

func TestCompileRedirectMap_SkipsInvalidEntries(t *testing.T) {
	hosts := map[string]redirectHostConfig{
		"not a hostname":  {RedirectTo: "https://www.example.com"},
		"bad.example.com": {RedirectTo: "ftp://www.example.com"},
		"sta.example.com": {RedirectTo: "https://www.example.com", Status: 418},
		"slash.example.com": {
			TrailingSlash: "add", // unknown policy
		},
		"rules.example.com": {
			Paths: []redirectPathRule{
				{From: "/broken(", To: "/new"},          // invalid regexp: skipped
				{From: "/old", To: "/new", Status: 302}, // valid: kept
			},
		},
		"GOOD.example.com": {RedirectTo: "https://www.example.com"},
	}

	m := compileRedirectMap(hosts)

	hostCount, ruleCount := m.counts()
	assert.Equal(t, 2, hostCount) // rules.example.com + good.example.com
	assert.Equal(t, 1, ruleCount)

	// Host keys are normalized to lower case
	location, status := m.redirectURL(
		url.URL{Scheme: "http", Host: "good.example.com", Path: "/"},
		url.URL{Scheme: "http", Host: "good.example.com"},
	)
	assert.Equal(t, "https://www.example.com", location)
	assert.Equal(t, 301, status)

	// The invalid rule is skipped; the valid one still fires
	location, status = m.redirectURL(
		url.URL{Scheme: "http", Host: "rules.example.com", Path: "/old"},
		url.URL{Scheme: "http", Host: "rules.example.com"},
	)
	assert.Equal(t, "http://rules.example.com/new", location)
	assert.Equal(t, 302, status)
}

func TestDynamicRedirectMap_HostRedirect(t *testing.T) {
	m := compileRedirectMap(map[string]redirectHostConfig{
		"legacy.example.com": {RedirectTo: "https://www.tenant.example"},
		"move.example.com":   {RedirectTo: "https://www.tenant.example", Status: 302, PreservePath: true},
		"loop.example.com":   {RedirectTo: "http://loop.example.com/"},
	})

	tests := []struct {
		name     string
		current  url.URL
		location string
		status   int
	}{
		{
			name:     "drops path and query without preserve_path",
			current:  url.URL{Scheme: "http", Host: "legacy.example.com", Path: "/deep/page", RawQuery: "q=1"},
			location: "https://www.tenant.example",
			status:   301,
		},
		{
			name:     "appends path and query with preserve_path",
			current:  url.URL{Scheme: "http", Host: "move.example.com", Path: "/deep/page", RawQuery: "q=1"},
			location: "https://www.tenant.example/deep/page?q=1",
			status:   302,
		},
		{
			name:     "self-loop is dropped",
			current:  url.URL{Scheme: "http", Host: "loop.example.com", Path: "/"},
			location: "",
		},
		{
			name:    "unknown host matches nothing",
			current: url.URL{Scheme: "http", Host: "other.example.com", Path: "/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			location, status := m.redirectURL(tt.current, url.URL{Scheme: tt.current.Scheme, Host: tt.current.Host})
			assert.Equal(t, tt.location, location)
			if tt.location != "" {
				assert.Equal(t, tt.status, status)
			}
		})
	}
}

func TestDynamicRedirectMap_PathRules(t *testing.T) {
	m := compileRedirectMap(map[string]redirectHostConfig{
		"www.tenant.example": {
			Paths: []redirectPathRule{
				{From: "/old-page", To: "/new-page"},
				{From: "/campaign/(.*)", To: "https://elsewhere.example/$1", Status: 302},
				{From: "/multi", To: "/first"},
				{From: "/multi", To: "/second"},
			},
		},
	})

	tests := []struct {
		name     string
		current  url.URL
		desired  url.URL
		location string
		status   int
	}{
		{
			name:     "relative target folds the desired scheme and host in one hop",
			current:  url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/old-page"},
			desired:  url.URL{Scheme: "https", Host: "www.tenant.example"},
			location: "https://www.tenant.example/new-page",
			status:   301,
		},
		{
			name:     "query rides along",
			current:  url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/old-page", RawQuery: "a=b"},
			desired:  url.URL{Scheme: "http", Host: "www.tenant.example"},
			location: "http://www.tenant.example/new-page?a=b",
			status:   301,
		},
		{
			name:     "capture group expansion to an absolute URL",
			current:  url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/campaign/spring"},
			desired:  url.URL{Scheme: "http", Host: "www.tenant.example"},
			location: "https://elsewhere.example/spring",
			status:   302,
		},
		{
			name:     "first match wins",
			current:  url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/multi"},
			desired:  url.URL{Scheme: "http", Host: "www.tenant.example"},
			location: "http://www.tenant.example/first",
			status:   301,
		},
		{
			name:    "whole-path anchoring",
			current: url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/old-page-extended"},
			desired: url.URL{Scheme: "http", Host: "www.tenant.example"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			location, status := m.redirectURL(tt.current, tt.desired)
			assert.Equal(t, tt.location, location)
			if tt.location != "" {
				assert.Equal(t, tt.status, status)
			}
		})
	}
}

func TestDynamicRedirectMap_TrailingSlash(t *testing.T) {
	m := compileRedirectMap(map[string]redirectHostConfig{
		"www.tenant.example": {
			TrailingSlash: "strip",
			Paths: []redirectPathRule{
				{From: "/keep/", To: "/kept"},
			},
		},
	})

	tests := []struct {
		name     string
		current  url.URL
		location string
		status   int
	}{
		{
			name:     "strips the trailing slash with the query preserved",
			current:  url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/foo/", RawQuery: "q=1"},
			location: "http://www.tenant.example/foo?q=1",
			status:   301,
		},
		{
			name:    "never for the root path",
			current: url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/"},
		},
		{
			name:    "paths without a trailing slash are untouched",
			current: url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/foo"},
		},
		{
			name:     "a matching path rule wins over the slash policy",
			current:  url.URL{Scheme: "http", Host: "www.tenant.example", Path: "/keep/"},
			location: "http://www.tenant.example/kept",
			status:   301,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			location, status := m.redirectURL(tt.current, url.URL{Scheme: tt.current.Scheme, Host: tt.current.Host})
			assert.Equal(t, tt.location, location)
			if tt.location != "" {
				assert.Equal(t, tt.status, status)
			}
		})
	}
}

func TestDynamicRedirectMap_NeverShadowsInternalPaths(t *testing.T) {
	m := compileRedirectMap(map[string]redirectHostConfig{
		"www.tenant.example": {
			RedirectTo:    "https://elsewhere.example",
			TrailingSlash: "strip",
			Paths:         []redirectPathRule{{From: "/.*", To: "/shadowed"}},
		},
	})

	for _, path := range []string{
		"/.well-known/acme-challenge/token123",
		"/.kamal-proxy/preflight/abc",
		"/.kamal-proxy/domains/refresh",
	} {
		t.Run(path, func(t *testing.T) {
			location, _ := m.redirectURL(
				url.URL{Scheme: "http", Host: "www.tenant.example", Path: path},
				url.URL{Scheme: "http", Host: "www.tenant.example"},
			)
			assert.Empty(t, location)
		})
	}
}
