package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAllowList(t testing.TB, allow, trusted []string, clientIPHeader string) *ipAllowList {
	t.Helper()

	list, err := newIPAllowList(allow, trusted, clientIPHeader)
	require.NoError(t, err)
	require.NotNil(t, list)

	return list
}

func testRequestFrom(peer string, headers ...string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = peer

	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}

	return req
}

func TestIPAllowList_ParseAcceptsAddressesAndPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		expected string
	}{
		{"v4 prefix", "10.0.0.0/8", "10.0.0.0/8"},
		{"bare v4 becomes a /32", "192.168.1.7", "192.168.1.7/32"},
		{"v6 prefix", "2001:db8::/32", "2001:db8::/32"},
		{"bare v6 becomes a /128", "::1", "::1/128"},
		{"host bits are masked off", "10.1.2.3/8", "10.0.0.0/8"},
		{"surrounding whitespace is ignored", "  10.0.0.0/8  ", "10.0.0.0/8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := parseIPPrefix(tt.entry)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, prefix.String())
		})
	}
}

func TestIPAllowList_ParseRejectsMalformedEntries(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{"empty", ""},
		{"not an address", "not-an-ip"},
		{"prefix out of range", "10.0.0.0/33"},
		{"v4-mapped prefix", "::ffff:10.0.0.0/104"},
		{"v4-mapped bare address", "::ffff:10.0.0.1"},
		{"zoned prefix", "fe80::1%eth0/64"},
		// ParseAddr accepts this and keeps the zone, but a zoned address matches
		// nothing, so storing it would silently do nothing.
		{"zoned bare address", "fe80::1%eth0"},
		{"host name", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseIPPrefix(tt.entry)
			require.Error(t, err)
		})
	}
}

func TestIPAllowList_MatchesNormalizedAddresses(t *testing.T) {
	tests := []struct {
		name     string
		allow    []string
		addr     string
		expected bool
	}{
		{"plain v4 inside", []string{"203.0.113.0/24"}, "203.0.113.5", true},
		{"plain v4 outside", []string{"203.0.113.0/24"}, "198.51.100.5", false},
		// The classic bypass: netip.Prefix.Contains reports false for a v4-mapped
		// v6 address against a v4 prefix unless it is unmapped first.
		{"v4-mapped v6 inside", []string{"203.0.113.0/24"}, "::ffff:203.0.113.5", true},
		{"v4-mapped v6 private", []string{"10.0.0.0/8"}, "::ffff:10.1.2.3", true},
		{"v4-mapped v6 outside", []string{"203.0.113.0/24"}, "::ffff:198.51.100.5", false},
		{"v6 inside", []string{"2001:db8::/32"}, "2001:db8::1", true},
		{"zoned v6 still matches", []string{"fe80::/10"}, "fe80::1%eth0", true},
		{"v6 loopback is not v4 loopback", []string{"127.0.0.0/8"}, "::1", false},
		{"any-v4 does not swallow v6", []string{"0.0.0.0/0"}, "2001:db8::1", false},
		{"multiple ranges, second matches", []string{"10.0.0.0/8", "203.0.113.0/24"}, "203.0.113.9", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := testAllowList(t, tt.allow, nil, "")
			addr, err := netip.ParseAddr(tt.addr)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, list.permits(normalizeAddr(addr)))
		})
	}
}

func TestIPAllowList_ZeroAddressMatchesNothing(t *testing.T) {
	list := testAllowList(t, []string{"0.0.0.0/0", "::/0"}, nil, "")

	// An unparseable peer resolves to the zero Addr; it must never be permitted,
	// even by a default route.
	assert.False(t, list.permits(netip.Addr{}))
}

func TestIPAllowList_IgnoresForwardedHeadersWithoutTrustedProxy(t *testing.T) {
	// The anti-regression test for the whole feature: with no --trusted-proxy,
	// no header can influence the decision.
	list := testAllowList(t, []string{"10.0.0.0/8"}, nil, "")

	tests := []struct {
		name    string
		headers []string
	}{
		{"no headers", nil},
		{"forged X-Forwarded-For", []string{"X-Forwarded-For", "10.0.0.1"}},
		{"forged X-Real-IP", []string{"X-Real-IP", "10.0.0.1"}},
		{"forged Forwarded", []string{"Forwarded", "for=10.0.0.1"}},
		{"forged CF-Connecting-IP", []string{"CF-Connecting-IP", "10.0.0.1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testRequestFrom("203.0.113.9:44321", tt.headers...)
			assert.False(t, list.permits(list.clientAddr(req)))
		})
	}
}

func TestIPAllowList_IgnoresForwardedHeaderFromUntrustedPeer(t *testing.T) {
	list := testAllowList(t, []string{"10.0.0.0/8"}, []string{"172.16.0.0/12"}, "")

	// The peer is not one of our proxies, so its claim carries no weight.
	req := testRequestFrom("203.0.113.9:44321", "X-Forwarded-For", "10.0.0.1")
	assert.False(t, list.permits(list.clientAddr(req)))

	// Including when the peer arrives over IPv6 and the trusted list is v4-only.
	req = testRequestFrom("[2001:db8::9]:44321", "X-Forwarded-For", "10.0.0.1")
	assert.False(t, list.permits(list.clientAddr(req)))
}

func TestIPAllowList_IgnoresForgedFirstForwardedHeaderLine(t *testing.T) {
	// http.Header.Get returns only the FIRST of repeated header lines. A hop that
	// appends its own line (HAProxy's option forwardfor does exactly this) leaves
	// the client's forged line first, so reading only that line hands the walk to
	// the attacker.
	list := testAllowList(t, []string{"10.0.0.0/8"}, []string{"172.16.0.0/12"}, "")

	req := testRequestFrom("172.16.5.9:44321",
		"X-Forwarded-For", "10.0.0.1", // forged by the client
		"X-Forwarded-For", "203.0.113.9", // appended by the real hop
	)

	assert.Equal(t, "203.0.113.9", list.clientAddr(req).String())
	assert.False(t, list.permits(list.clientAddr(req)))
}

func TestIPAllowList_ResolvesThroughTrustedProxy(t *testing.T) {
	tests := []struct {
		name     string
		trusted  []string
		peer     string
		headers  []string
		expected string
	}{
		{
			name:     "single hop",
			trusted:  []string{"172.16.0.0/12"},
			peer:     "172.16.5.9:44321",
			headers:  []string{"X-Forwarded-For", "10.0.0.1"},
			expected: "10.0.0.1",
		},
		{
			name:     "two hops, both trusted, client is leftmost",
			trusted:  []string{"172.16.0.0/12", "192.0.2.0/24"},
			peer:     "172.16.5.9:44321",
			headers:  []string{"X-Forwarded-For", "10.0.0.1, 192.0.2.7"},
			expected: "10.0.0.1",
		},
		{
			name:     "untrusted entry to the right wins over one further left",
			trusted:  []string{"172.16.0.0/12"},
			peer:     "172.16.5.9:44321",
			headers:  []string{"X-Forwarded-For", "10.0.0.1, 203.0.113.9"},
			expected: "203.0.113.9",
		},
		{
			name:     "entries carrying ports",
			trusted:  []string{"172.16.0.0/12"},
			peer:     "172.16.5.9:44321",
			headers:  []string{"X-Forwarded-For", "10.0.0.1:8080"},
			expected: "10.0.0.1",
		},
		{
			name:     "bracketed v6 entry carrying a port",
			trusted:  []string{"172.16.0.0/12"},
			peer:     "172.16.5.9:44321",
			headers:  []string{"X-Forwarded-For", "[2001:db8::1]:443"},
			expected: "2001:db8::1",
		},
		{
			name:     "whitespace around entries",
			trusted:  []string{"172.16.0.0/12"},
			peer:     "172.16.5.9:44321",
			headers:  []string{"X-Forwarded-For", "  10.0.0.1  ,  172.16.5.9  "},
			expected: "10.0.0.1",
		},
		{
			name:    "three hops across two header lines",
			trusted: []string{"172.16.0.0/12", "192.0.2.0/24"},
			peer:    "172.16.5.9:44321",
			headers: []string{
				"X-Forwarded-For", "10.0.0.1",
				"X-Forwarded-For", "192.0.2.7",
			},
			expected: "10.0.0.1",
		},
		{
			name:     "v4-mapped entry is unmapped",
			trusted:  []string{"172.16.0.0/12"},
			peer:     "172.16.5.9:44321",
			headers:  []string{"X-Forwarded-For", "::ffff:10.0.0.1"},
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := testAllowList(t, []string{"10.0.0.0/8"}, tt.trusted, "")
			req := testRequestFrom(tt.peer, tt.headers...)

			assert.Equal(t, tt.expected, list.clientAddr(req).String())
		})
	}
}

func TestIPAllowList_DeniesUnresolvableForwardedChain(t *testing.T) {
	// Falling back to the peer here would be a bypass whenever the allow list
	// contains the proxy's own range, so an unresolvable chain denies.
	tests := []struct {
		name    string
		headers []string
	}{
		{"header absent", nil},
		{"header empty", []string{"X-Forwarded-For", ""}},
		{"chain entirely trusted", []string{"X-Forwarded-For", "172.16.5.9"}},
		{"junk nearest hop", []string{"X-Forwarded-For", "10.0.0.1, evil"}},
		{"all junk", []string{"X-Forwarded-For", "evil, worse"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := testAllowList(t, []string{"10.0.0.0/8", "172.16.0.0/12"}, []string{"172.16.0.0/12"}, "")
			req := testRequestFrom("172.16.5.9:44321", tt.headers...)

			assert.False(t, list.clientAddr(req).IsValid())
			assert.False(t, list.permits(list.clientAddr(req)))
		})
	}
}

func TestIPAllowList_ReadsTheOperatorNamedClientIPHeader(t *testing.T) {
	// ClientIPMiddleware overwrites X-Forwarded-For from the named header, so the
	// allow list reads the named header itself rather than the value that
	// middleware left behind.
	list := testAllowList(t, []string{"10.0.0.0/8"}, []string{"172.16.0.0/12"}, "CF-Connecting-IP")

	req := testRequestFrom("172.16.5.9:44321",
		"CF-Connecting-IP", "10.0.0.1",
		"X-Forwarded-For", "203.0.113.9",
	)

	assert.Equal(t, "10.0.0.1", list.clientAddr(req).String())
	assert.True(t, list.permits(list.clientAddr(req)))
}

func TestIPAllowList_DeniesUnparseablePeer(t *testing.T) {
	list := testAllowList(t, []string{"10.0.0.0/8"}, nil, "")

	for _, peer := range []string{"", "/tmp/kamal-proxy.sock", "garbage"} {
		t.Run(peer, func(t *testing.T) {
			req := testRequestFrom(peer)
			assert.False(t, list.permits(list.clientAddr(req)))
		})
	}
}

func TestIPAllowList_ChainLengthIsBounded(t *testing.T) {
	list := testAllowList(t, []string{"10.0.0.0/8"}, []string{"172.16.0.0/12"}, "")

	// The client is the leftmost entry, with more trusted hops appended to its
	// right than we are willing to walk back through.
	chain := "10.0.0.1"
	for range forwardedChainLimit + 5 {
		chain += ", 172.16.5.9"
	}

	req := testRequestFrom("172.16.5.9:44321", "X-Forwarded-For", chain)

	// The client entry sits beyond the hop limit, so the chain is unresolvable
	// rather than walked indefinitely.
	assert.False(t, list.clientAddr(req).IsValid())
}

func TestServiceOptions_ValidateAllowIPs(t *testing.T) {
	tests := []struct {
		name           string
		allowIPs       []string
		trustedProxies []string
		clientIPHeader string
		expectedError  string
	}{
		{name: "no options"},
		{name: "allow only", allowIPs: []string{"10.0.0.0/8"}},
		{name: "allow with trusted proxy", allowIPs: []string{"10.0.0.0/8"}, trustedProxies: []string{"172.16.0.0/12"}},
		{
			name:           "allow with client ip header and trusted proxy",
			allowIPs:       []string{"10.0.0.0/8"},
			trustedProxies: []string{"172.16.0.0/12"},
			clientIPHeader: "CF-Connecting-IP",
		},
		{
			name:          "malformed allow entry",
			allowIPs:      []string{"nonsense"},
			expectedError: "allow-ip",
		},
		{
			name:           "malformed trusted entry",
			allowIPs:       []string{"10.0.0.0/8"},
			trustedProxies: []string{"nonsense"},
			expectedError:  "trusted-proxy",
		},
		{
			name:           "trusted proxy without an allow list",
			trustedProxies: []string{"172.16.0.0/12"},
			expectedError:  "trusted-proxy requires allow-ip",
		},
		{
			name:           "a default route cannot be trusted",
			allowIPs:       []string{"10.0.0.0/8"},
			trustedProxies: []string{"0.0.0.0/0"},
			expectedError:  "trusted-proxy cannot contain a default route",
		},
		{
			name:           "a v6 default route cannot be trusted either",
			allowIPs:       []string{"10.0.0.0/8"},
			trustedProxies: []string{"::/0"},
			expectedError:  "trusted-proxy cannot contain a default route",
		},
		{
			name:           "client ip header without trusted proxy is rejected",
			allowIPs:       []string{"10.0.0.0/8"},
			clientIPHeader: "CF-Connecting-IP",
			expectedError:  "allow-ip with client-ip-header requires trusted-proxy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := defaultServiceOptions
			options.AllowIPs = tt.allowIPs
			options.TrustedProxies = tt.trustedProxies
			options.ClientIPHeader = tt.clientIPHeader

			err := options.Validate()

			if tt.expectedError == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, ErrServiceOptionsInvalid)
			require.ErrorContains(t, err, tt.expectedError)
		})
	}
}

func BenchmarkIPAllowList_Permits(b *testing.B) {
	list, err := newIPAllowList([]string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.0/24",
		"198.51.100.0/24", "2001:db8::/32", "fd00::/8", "100.64.0.0/10",
	}, nil, "")
	if err != nil {
		b.Fatal(err)
	}

	req := testRequestFrom("203.0.113.9:44321")

	b.ReportAllocs()
	for b.Loop() {
		list.permits(list.clientAddr(req))
	}
}

func TestMetricsAllowList(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("metrics"))
	})

	tests := []struct {
		name           string
		allowed        []string
		peer           string
		expectedStatus int
	}{
		{"no list serves everyone", nil, testDeniedPeer, http.StatusOK},
		{"matching peer", []string{"10.0.0.0/8"}, testAllowedPeer, http.StatusOK},
		{"non-matching peer", []string{"10.0.0.0/8"}, testDeniedPeer, http.StatusForbidden},
		{"v4-mapped v6 peer still matches", []string{"10.0.0.0/8"}, "[::ffff:10.0.0.5]:44321", http.StatusOK},
		{"unparseable peer", []string{"10.0.0.0/8"}, "garbage", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, err := parseIPPrefixes(tt.allowed, "metrics-allow-ip")
			require.NoError(t, err)

			handler := withMetricsAllowList(prefixes, backend)

			req := testRequestFrom(tt.peer)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Result().StatusCode)
		})
	}
}

func TestMetricsAllowList_InvalidEntryIsRejectedEvenWhenMetricsAreOff(t *testing.T) {
	config := testConfig(t)
	config.MetricsPort = 0
	config.MetricsAllowIPs = []string{"not-an-ip"}

	server := NewServer(config, testRouter(t))

	err := server.startMetricsServer()

	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
	require.ErrorContains(t, err, "metrics-allow-ip")
}
