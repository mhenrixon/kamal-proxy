package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDomainList(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected []string
		errorMsg string
	}{
		{
			name:     "valid domains",
			payload:  `{"domains": ["a.example.com", "b.example.com"]}`,
			expected: []string{"a.example.com", "b.example.com"},
		},
		{
			name:     "normalizes case and dedupes",
			payload:  `{"domains": ["A.Example.COM", "a.example.com"]}`,
			expected: []string{"a.example.com"},
		},
		{
			name:     "skips wildcards",
			payload:  `{"domains": ["*.example.com", "a.example.com"]}`,
			expected: []string{"a.example.com"},
		},
		{
			name:     "skips invalid hostnames",
			payload:  `{"domains": ["not a hostname", "single-label", "-bad.example.com", "1.2.3.4", "good.example.com"]}`,
			expected: []string{"good.example.com"},
		},
		{
			name:     "empty list",
			payload:  `{"domains": []}`,
			expected: []string{},
		},
		{
			name:     "invalid JSON",
			payload:  `{"domains": [`,
			errorMsg: "failed to parse domain list",
		},
		{
			name:     "too many entries",
			payload:  fmt.Sprintf(`{"domains": [%s"last.example.com"]}`, strings.Repeat(`"x.example.com",`, 10000)),
			errorMsg: "too many domains",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domains, err := parseDomainList(strings.NewReader(tt.payload))
			if tt.errorMsg != "" {
				require.ErrorContains(t, err, tt.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, domains)
		})
	}
}

func TestParseDomainList_RejectsOversizePayload(t *testing.T) {
	payload := `{"domains": ["` + strings.Repeat("a", int(MB)) + `.example.com"]}`
	_, err := parseDomainList(strings.NewReader(payload))
	require.ErrorContains(t, err, "domain list too large")
}

func TestValidDynamicDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"xn--nxasmq6b.example.com", true},
		{"a-b.example.com", true},
		{"example", false},                                // single label
		{"-bad.example.com", false},                       // leading hyphen
		{"bad-.example.com", false},                       // trailing hyphen
		{"1.2.3.4", false},                                // IP address
		{"*.example.com", false},                          // wildcard
		{"ex ample.com", false},                           // space
		{"", false},                                       //
		{strings.Repeat("a", 64) + ".example.com", false}, // label too long
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.valid, validDynamicDomain(tt.domain))
		})
	}
}

func TestDomainSource_PollAppliesDomainsAndHonorsETag(t *testing.T) {
	var mu sync.Mutex
	requests := []*http.Request{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Clone(r.Context()))
		mu.Unlock()

		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, `{"domains": ["tenant.example.com"]}`)
	}))
	t.Cleanup(server.Close)

	applied := [][]string{}
	source := newDomainSource(domainSourceConfig{
		Service: "service1",
		Source:  server.URL + "/domains",
		Token:   "secret-token",
		OnDomains: func(domains []string) {
			applied = append(applied, domains)
		},
	})

	source.poll()
	source.poll()

	require.Len(t, requests, 2)
	assert.Equal(t, "Bearer secret-token", requests[0].Header.Get("Authorization"))
	assert.Empty(t, requests[0].Header.Get("If-None-Match"))
	assert.Equal(t, `"v1"`, requests[1].Header.Get("If-None-Match"))

	// The 304 response must not re-apply the domain list
	require.Len(t, applied, 1)
	assert.Equal(t, []string{"tenant.example.com"}, applied[0])
}

func TestDomainSource_PathModeResolvesAgainstTarget(t *testing.T) {
	var seenPath, seenHost string

	server, targetHost := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenHost = r.Host
		fmt.Fprint(w, `{"domains": ["tenant.example.com"]}`)
	})
	_ = server

	applied := [][]string{}
	source := newDomainSource(domainSourceConfig{
		Service: "service1",
		Source:  "/api/v1/domains",
		Endpoint: func() (string, string, error) {
			return "http://" + targetHost, "app.internal", nil
		},
		OnDomains: func(domains []string) {
			applied = append(applied, domains)
		},
	})

	source.poll()

	assert.Equal(t, "/api/v1/domains", seenPath)
	assert.Equal(t, "app.internal", seenHost)
	require.Len(t, applied, 1)
}

func TestDomainSource_RefreshTriggersImmediatePoll(t *testing.T) {
	polled := make(chan struct{}, 10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polled <- struct{}{}
		fmt.Fprint(w, `{"domains": []}`)
	}))
	t.Cleanup(server.Close)

	source := newDomainSource(domainSourceConfig{
		Service:   "service1",
		Source:    server.URL,
		Interval:  time.Hour, // ticker will not fire during the test
		OnDomains: func(domains []string) {},
	})

	source.Start()
	t.Cleanup(source.Stop)

	// Initial poll on start
	select {
	case <-polled:
	case <-time.After(5 * time.Second):
		t.Fatal("no initial poll")
	}

	source.Refresh()

	select {
	case <-polled:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not trigger a poll")
	}
}

func TestDomainSource_KeepsLastSetOnFetchError(t *testing.T) {
	healthy := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `{"domains": ["tenant.example.com"]}`)
	}))
	t.Cleanup(server.Close)

	applied := [][]string{}
	source := newDomainSource(domainSourceConfig{
		Service:   "service1",
		Source:    server.URL,
		OnDomains: func(domains []string) { applied = append(applied, domains) },
	})

	source.poll()
	healthy = false
	source.poll()

	// The failed poll must not clear or re-apply anything
	require.Len(t, applied, 1)
	assert.Equal(t, []string{"tenant.example.com"}, applied[0])
}
