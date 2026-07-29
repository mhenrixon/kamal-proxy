package server

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMinTLSVersion(t *testing.T) {
	tests := []struct {
		value         string
		expected      uint16
		expectedError string
	}{
		{value: "", expected: tls.VersionTLS12},
		{value: "1.2", expected: tls.VersionTLS12},
		{value: "1.3", expected: tls.VersionTLS13},
		{value: " 1.3 ", expected: tls.VersionTLS13},
		{value: "TLSv1.3", expected: tls.VersionTLS13},
		// The grammar basecamp/kamal-proxy#199 uses, so an upstream config keeps working.
		{value: "tls1_2", expected: tls.VersionTLS12},
		{value: "tls1_3", expected: tls.VersionTLS13},

		{value: "1.0", expectedError: "TLS 1.0 cannot be enabled"},
		{value: "1.1", expectedError: "TLS 1.1 cannot be enabled"},
		{value: "tls1_0", expectedError: "TLS 1.0 cannot be enabled"},
		{value: "TLSv1.1", expectedError: "TLS 1.1 cannot be enabled"},

		{value: "1.4", expectedError: `"1.4" is not a TLS version`},
		{value: "tls13", expectedError: `"tls13" is not a TLS version`},
		{value: "yes", expectedError: `"yes" is not a TLS version`},
		{value: "tlsv", expectedError: `"tlsv" is not a TLS version`},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			version, err := ParseMinTLSVersion(tt.value)

			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				require.ErrorContains(t, err, "min-tls")
				assert.Zero(t, version)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, version)
		})
	}
}

func TestServer_MinTLSVersionIsEnforcedOnTheHTTPSListener(t *testing.T) {
	t.Run("the default refuses TLS 1.1 and serves TLS 1.2", func(t *testing.T) {
		server := testMinTLSServer(t, "", nil)

		_, err := testRequestWithTLSVersions(t, server, tls.VersionTLS10, tls.VersionTLS11)
		require.Error(t, err)
		assert.ErrorContains(t, err, "protocol version not supported")

		resp, err := testRequestWithTLSVersions(t, server, tls.VersionTLS12, tls.VersionTLS12)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("1.3 refuses a TLS 1.2 client", func(t *testing.T) {
		server := testMinTLSServer(t, "1.3", nil)

		_, err := testRequestWithTLSVersions(t, server, tls.VersionTLS12, tls.VersionTLS12)
		require.Error(t, err)
		assert.ErrorContains(t, err, "protocol version not supported")
	})

	t.Run("1.3 still serves TLS 1.3", func(t *testing.T) {
		server := testMinTLSServer(t, "1.3", nil)

		resp, err := testRequestWithTLSVersions(t, server, tls.VersionTLS13, tls.VersionTLS13)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotNil(t, resp.TLS)
		assert.Equal(t, uint16(tls.VersionTLS13), resp.TLS.Version)
	})
}

// Hosts requiring a client certificate get a REPLACEMENT tls.Config, and Go
// negotiates the version against that config rather than the listener's. Only
// because clientCertificateConfig clones does the minimum survive; building a
// fresh config there downgrades every mTLS host back to TLS 1.2 with no error
// anywhere. This test is the tripwire for that.
func TestServer_MinTLSVersionAppliesToMutualTLSHosts(t *testing.T) {
	ca := generateTestCA(t)
	server := testMinTLSServer(t, "1.3", ca)
	clientCert := ca.issueClientCertificate(t)

	t.Run("refuses a valid client certificate offered over TLS 1.2", func(t *testing.T) {
		_, err := testRequestWithTLSVersions(t, server, tls.VersionTLS12, tls.VersionTLS12, clientCert)
		require.Error(t, err)
		assert.ErrorContains(t, err, "protocol version not supported")
	})

	t.Run("accepts the same certificate over TLS 1.3", func(t *testing.T) {
		resp, err := testRequestWithTLSVersions(t, server, tls.VersionTLS13, tls.VersionTLS13, clientCert)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotNil(t, resp.TLS)
		assert.Equal(t, uint16(tls.VersionTLS13), resp.TLS.Version)
	})
}

func TestServer_InvalidMinTLSFailsToStart(t *testing.T) {
	tests := []string{"1.1", "sslv3"}

	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			config := testConfig(t)
			config.MinTLS = value

			server := NewServer(config, NewRouter(config.StatePath()))
			err := server.Start()

			require.ErrorContains(t, err, "min-tls")
		})
	}
}

// Helpers

func testMinTLSServer(t *testing.T, minTLS string, clientCA *testCA) *Server {
	t.Helper()

	config := testConfig(t)
	config.MinTLS = minTLS
	server := testServerWithConfig(t, config)

	certPath, keyPath := prepareTestCertificateFiles(t)
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"localhost"}
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath
	if clientCA != nil {
		serviceOptions.TLSClientCACertificatePath = clientCA.certPath
	}

	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
	testDeployTarget(t, target, server, serviceOptions)

	return server
}

// testRequestWithTLSVersions drives a request inside an exact TLS version
// window. Both bounds are set on purpose: Go's own client minimum is TLS 1.2,
// so a MaxVersion of 1.1 alone makes the config self-contradictory and the
// request fails locally, before a byte reaches the listener - which would pass
// a refusal test for entirely the wrong reason.
func testRequestWithTLSVersions(tb testing.TB, server *Server, minVersion, maxVersion uint16, certs ...tls.Certificate) (*http.Response, error) {
	tb.Helper()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         minVersion,
			MaxVersion:         maxVersion,
			Certificates:       certs,
		},
		ForceAttemptHTTP2: true,
	}
	tb.Cleanup(transport.CloseIdleConnections)

	return testRequestUsingTransport(server, transport)
}
