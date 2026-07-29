package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMutualTLSServer(t *testing.T, ca *testCA, hosts []string) *Server {
	t.Helper()

	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
	server := testServer(t, false)

	certPath, keyPath := prepareTestCertificateFiles(t)
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = hosts
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath
	serviceOptions.TLSClientCACertificatePath = ca.certPath

	testDeployTarget(t, target, server, serviceOptions)
	return server
}

func testRequestWithClientCertificate(tb testing.TB, server *Server, certs []tls.Certificate, forceHTTP2 bool) (*http.Response, error) {
	tb.Helper()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       certs,
		},
		ForceAttemptHTTP2: forceHTTP2,
	}

	return testRequestUsingTransport(server, transport)
}

func TestServer_MutualTLS(t *testing.T) {
	ca := generateTestCA(t)
	server := testMutualTLSServer(t, ca, []string{"localhost"})

	t.Run("rejects a client that presents no certificate", func(t *testing.T) {
		_, err := testRequestUsingHTTP11(t, server)
		assert.Error(t, err)
	})

	t.Run("rejects a certificate signed by a different CA", func(t *testing.T) {
		other := generateTestCA(t)

		_, err := testRequestWithClientCertificate(t, server, []tls.Certificate{other.issueClientCertificate(t)}, false)
		assert.Error(t, err)
	})

	t.Run("accepts a certificate signed by the configured CA", func(t *testing.T) {
		resp, err := testRequestWithClientCertificate(t, server, []tls.Certificate{ca.issueClientCertificate(t)}, false)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Requiring client certificates swaps in a different tls.Config for the
	// connection. Building that config from scratch rather than cloning the
	// listener's would silently drop ALPN, downgrading every mTLS host to
	// HTTP/1.1 and breaking tls-alpn-01 challenges.
	t.Run("still negotiates HTTP/2", func(t *testing.T) {
		resp, err := testRequestWithClientCertificate(t, server, []tls.Certificate{ca.issueClientCertificate(t)}, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "HTTP/2.0", resp.Proto)
	})
}

// Without --tls-client-ca-path nothing about the handshake changes.
func TestServer_WithoutMutualTLSClientCertificatesAreNotRequired(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
	server := testServer(t, false)

	certPath, keyPath := prepareTestCertificateFiles(t)
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"localhost"}
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath

	testDeployTarget(t, target, server, serviceOptions)

	resp, err := testRequestUsingHTTP11(t, server)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRouter_ClientCAsForHost(t *testing.T) {
	ca := generateTestCA(t)

	t.Run("returns the pool for a host the service serves", func(t *testing.T) {
		router := testRouter(t)
		_, target := testBackend(t, "first", http.StatusOK)

		certPath, keyPath := prepareTestCertificateFiles(t)
		serviceOptions := defaultServiceOptions
		serviceOptions.Hosts = []string{"app.example.com"}
		serviceOptions.TLSEnabled = true
		serviceOptions.TLSCertificatePath = certPath
		serviceOptions.TLSPrivateKeyPath = keyPath
		serviceOptions.TLSClientCACertificatePath = ca.certPath

		require.NoError(t, router.DeployService("mtls", []string{target}, defaultEmptyReaders,
			serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

		assert.NotNil(t, router.clientCAsForHost("app.example.com"))
	})

	t.Run("returns nil for a service without a client CA", func(t *testing.T) {
		router := testRouter(t)
		_, target := testBackend(t, "first", http.StatusOK)

		serviceOptions := defaultServiceOptions
		serviceOptions.Hosts = []string{"plain.example.com"}

		require.NoError(t, router.DeployService("plain", []string{target}, defaultEmptyReaders,
			serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

		assert.Nil(t, router.clientCAsForHost("plain.example.com"))
	})

	t.Run("returns nil when no service claims the host", func(t *testing.T) {
		router := testRouter(t)

		assert.Nil(t, router.clientCAsForHost("nobody.example.com"))
	})
}

// Only an on-demand (or dynamic-domains) service can hold the catch-all binding
// with TLS on -- validation demands a host otherwise. Combined with a client CA
// that is the Cloudflare origin pull shape: one origin, every host behind it.
// The consequence worth pinning is that such a service's client CA governs every
// hostname no other service claims, including ones never named on the command
// line.
func TestRouter_ClientCAsForHost_OnDemandCatchAllCoversUnclaimedHosts(t *testing.T) {
	ca := generateTestCA(t)

	router := testRouter(t)
	_, catchAllTarget := testBackend(t, "catch-all", http.StatusOK)
	_, namedTarget := testBackend(t, "named", http.StatusOK)

	catchAllOptions := defaultServiceOptions
	catchAllOptions.TLSEnabled = true
	catchAllOptions.TLSOnDemandURL = "/ask"
	catchAllOptions.ACMECachePath = t.TempDir()
	catchAllOptions.TLSClientCACertificatePath = ca.certPath

	require.NoError(t, router.DeployService("catchall", []string{catchAllTarget}, defaultEmptyReaders,
		catchAllOptions, defaultTargetOptions, defaultDeploymentOptions))

	namedOptions := defaultServiceOptions
	namedOptions.Hosts = []string{"named.example.com"}

	require.NoError(t, router.DeployService("named", []string{namedTarget}, defaultEmptyReaders,
		namedOptions, defaultTargetOptions, defaultDeploymentOptions))

	assert.NotNil(t, router.clientCAsForHost("anything.example.com"),
		"the catch-all service's client CA governs hosts nobody else claims")
	assert.Nil(t, router.clientCAsForHost("named.example.com"),
		"a host-scoped service is unaffected by the catch-all's client CA")
}

// GetConfigForClient runs on every TLS handshake now, not just mTLS ones, so the
// cost of the nil path matters as much as the clone.
func BenchmarkServer_ClientCertificateConfig(b *testing.B) {
	router := NewRouter(filepath.Join(b.TempDir(), "state.json"))
	router.services.Set(&Service{
		name:    "plain",
		options: normalizedServiceOptions(ServiceOptions{Hosts: []string{"plain.example.com"}}),
	})
	router.services.Set(&Service{
		name:      "mtls",
		options:   normalizedServiceOptions(ServiceOptions{Hosts: []string{"mtls.example.com"}}),
		clientCAs: x509.NewCertPool(),
	})

	server := &Server{router: router}
	base := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	getConfig := server.clientCertificateConfig(base)

	b.Run("host without client CA", func(b *testing.B) {
		hello := &tls.ClientHelloInfo{ServerName: "plain.example.com"}

		b.ReportAllocs()
		for b.Loop() {
			_, _ = getConfig(hello)
		}
	})

	b.Run("host requiring client certificates", func(b *testing.B) {
		hello := &tls.ClientHelloInfo{ServerName: "mtls.example.com"}

		b.ReportAllocs()
		for b.Loop() {
			_, _ = getConfig(hello)
		}
	})
}

// A client CA without --tls is a misconfiguration that would otherwise be
// silently ignored, leaving an origin the operator believes is locked down open.
func TestServiceOptions_ClientCARequiresTLS(t *testing.T) {
	options := defaultServiceOptions
	options.Hosts = []string{"app.example.com"}
	options.TLSClientCACertificatePath = "/etc/ca.pem"

	err := options.Validate()
	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
	assert.Contains(t, err.Error(), "TLS must be enabled to require client certificates")
}

// A CA path that cannot be loaded must fail the deploy rather than bring the
// service up without the client verification it asked for.
func TestService_UnloadableClientCAFailsDeploy(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "first", http.StatusOK)

	certPath, keyPath := prepareTestCertificateFiles(t)
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"app.example.com"}
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath
	serviceOptions.TLSClientCACertificatePath = filepath.Join(t.TempDir(), "missing.pem")

	err := router.DeployService("mtls", []string{target}, defaultEmptyReaders,
		serviceOptions, defaultTargetOptions, defaultDeploymentOptions)
	require.ErrorIs(t, err, ErrorUnableToLoadClientCACertificate)
}

// Old state files predate the field; they must restore with mTLS simply off.
func TestService_ClientCASurvivesStateRoundTrip(t *testing.T) {
	ca := generateTestCA(t)

	options := defaultServiceOptions
	options.Hosts = []string{"app.example.com"}
	options.TLSClientCACertificatePath = ca.certPath

	encoded, err := json.Marshal(options)
	require.NoError(t, err)

	var decoded ServiceOptions
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, ca.certPath, decoded.TLSClientCACertificatePath)

	var legacy ServiceOptions
	require.NoError(t, json.Unmarshal([]byte(`{"hosts":["app.example.com"],"tls_enabled":true}`), &legacy))
	assert.Empty(t, legacy.TLSClientCACertificatePath)
}
