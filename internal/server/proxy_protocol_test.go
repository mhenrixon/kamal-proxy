package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPeerAddr string

func (a testPeerAddr) Network() string { return "tcp" }
func (a testPeerAddr) String() string  { return string(a) }

func TestProxyProtocolPolicy(t *testing.T) {
	tests := []struct {
		name     string
		allowed  []string
		peer     string
		expected proxyproto.Policy
	}{
		{
			name:     "no allow list trusts every peer",
			allowed:  nil,
			peer:     "192.0.2.10:45678",
			expected: proxyproto.USE,
		},
		{
			name:     "peer inside an allowed range",
			allowed:  []string{"10.0.0.0/8"},
			peer:     "10.1.2.3:45678",
			expected: proxyproto.USE,
		},
		{
			name:     "peer outside every allowed range",
			allowed:  []string{"10.0.0.0/8"},
			peer:     "192.0.2.10:45678",
			expected: proxyproto.IGNORE,
		},
		{
			name:     "peer matching an exact address entry",
			allowed:  []string{"192.0.2.10"},
			peer:     "192.0.2.10:45678",
			expected: proxyproto.USE,
		},
		{
			name:     "IPv6 peer inside an IPv6 range",
			allowed:  []string{"2001:db8::/32"},
			peer:     "[2001:db8::1]:443",
			expected: proxyproto.USE,
		},
		{
			name:     "IPv4-mapped peer matches a plain IPv4 range",
			allowed:  []string{"10.0.0.0/8"},
			peer:     "[::ffff:10.1.2.3]:443",
			expected: proxyproto.USE,
		},
		{
			name:     "unparseable peer is not trusted",
			allowed:  []string{"10.0.0.0/8"},
			peer:     "bogus",
			expected: proxyproto.IGNORE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := parseIPPrefixes(tt.allowed, "proxy-protocol-allow-ip")
			require.NoError(t, err)

			policy := proxyProtocolPolicy(allowed)
			got, err := policy(proxyproto.ConnPolicyOptions{Upstream: testPeerAddr(tt.peer)})
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestServer_ProxyProtocol(t *testing.T) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 45678}
	proxyAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.99"), Port: 80}

	writeV1Header := func(conn net.Conn) error {
		_, err := io.WriteString(conn, "PROXY TCP4 203.0.113.7 198.51.100.99 45678 80\r\n")
		return err
	}

	tests := []struct {
		name        string
		allowIPs    []string
		writeHeader func(conn net.Conn) error
		expectedFor string
	}{
		{
			name:        "v1 header sets the client address",
			writeHeader: writeV1Header,
			expectedFor: "203.0.113.7",
		},
		{
			name: "v2 header sets the client address",
			writeHeader: func(conn net.Conn) error {
				_, err := proxyproto.HeaderProxyFromAddrs(2, clientAddr, proxyAddr).WriteTo(conn)
				return err
			},
			expectedFor: "203.0.113.7",
		},
		{
			name:        "connection without a header keeps its peer address",
			writeHeader: func(conn net.Conn) error { return nil },
			expectedFor: "127.0.0.1",
		},
		{
			name:        "header from an allowed peer is honoured",
			allowIPs:    []string{"127.0.0.0/8"},
			writeHeader: writeV1Header,
			expectedFor: "203.0.113.7",
		},
		{
			name:        "header from a peer outside the allow list is ignored",
			allowIPs:    []string{"203.0.113.0/24"},
			writeHeader: writeV1Header,
			expectedFor: "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(t)
			config.ProxyProtocol = true
			config.ProxyProtocolAllowIPs = tt.allowIPs
			server := testServerWithConfig(t, config)

			testDeployTarget(t, testForwardedForEchoTarget(t), server, defaultServiceOptions)

			body := testProxyProtocolGet(t, server.HttpPort(), tt.writeHeader, false)
			assert.Equal(t, tt.expectedFor, body)
		})
	}
}

func TestServer_ProxyProtocolTLS(t *testing.T) {
	// The PROXY header must be read from the raw stream before the TLS
	// handshake; a header-then-handshake client proves the wrap ordering.
	config := testConfig(t)
	config.ProxyProtocol = true
	server := testServerWithConfig(t, config)

	certPath, keyPath := prepareTestCertificateFiles(t)
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"localhost"}
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath

	testDeployTarget(t, testForwardedForEchoTarget(t), server, serviceOptions)

	body := testProxyProtocolGet(t, server.HttpsPort(), func(conn net.Conn) error {
		_, err := io.WriteString(conn, "PROXY TCP4 203.0.113.7 198.51.100.99 45678 443\r\n")
		return err
	}, true)
	assert.Equal(t, "203.0.113.7", body)
}

func TestServer_ProxyProtocolDisabledDoesNotParseHeaders(t *testing.T) {
	server := testServer(t, false)

	testDeployTarget(t, testForwardedForEchoTarget(t), server, defaultServiceOptions)

	// Without the flag the preamble is not stripped, so it reaches net/http
	// as a malformed request line rather than silently rewriting addresses.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.HttpPort()))
	require.NoError(t, err)
	defer conn.Close()

	_, err = io.WriteString(conn, "PROXY TCP4 203.0.113.7 198.51.100.99 45678 80\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)

	response, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Contains(t, string(response), "400 Bad Request")
}

func TestServer_ProxyProtocolInvalidAllowIPFailsBoot(t *testing.T) {
	// Parsed even while disabled, so a typo fails the boot rather than
	// waiting until someone turns the flag on.
	config := testConfig(t)
	config.ProxyProtocolAllowIPs = []string{"not-an-address"}

	server := NewServer(config, NewRouter(config.StatePath()))
	require.Error(t, server.Start())
}

// Helpers

// testForwardedForEchoTarget echoes the X-Forwarded-For header the backend
// received, whose final entry is the client address the proxy resolved.
func testForwardedForEchoTarget(t *testing.T) *Target {
	t.Helper()

	return testTarget(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header.Get("X-Forwarded-For"))
	})
}

// testProxyProtocolGet issues GET / through a transport that writes a PROXY
// protocol preamble on the raw connection before HTTP -- and before the TLS
// handshake when useTLS is set, exactly as a load balancer would. writeHeader
// runs on the transport's dial goroutine, so it reports failure by returning
// an error rather than failing the test from off the test goroutine.
func testProxyProtocolGet(t *testing.T, port int, writeHeader func(conn net.Conn) error, useTLS bool) string {
	t.Helper()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			if err := writeHeader(conn); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	scheme := "http"
	if useTLS {
		scheme = "https"
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	resp, err := (&http.Client{Transport: transport}).Get(fmt.Sprintf("%s://localhost:%d/", scheme, port))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return string(body)
}
