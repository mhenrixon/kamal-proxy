package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	defaultHealthCheckConfig = HealthCheckConfig{Path: DefaultHealthCheckPath, Port: DefaultHealthCheckPort, Interval: DefaultHealthCheckInterval, Timeout: time.Second * 5}
	defaultEmptyReaders      = []string{}
	defaultServiceOptions    = ServiceOptions{TLSRedirect: true}
	defaultTargetOptions     = TargetOptions{HealthCheckConfig: defaultHealthCheckConfig, ResponseTimeout: DefaultTargetTimeout}
	defaultDeploymentOptions = DeploymentOptions{DeployTimeout: DefaultDeployTimeout, DrainTimeout: DefaultDrainTimeout, Force: false}
)

func testTarget(t testing.TB, handler http.HandlerFunc) *Target {
	t.Helper()

	_, targetURL := testBackendWithHandler(t, handler)

	target, err := NewTarget(targetURL, defaultTargetOptions)
	require.NoError(t, err)
	return target
}

func testReadOnlyTarget(t testing.TB, handler http.HandlerFunc) *Target {
	t.Helper()

	_, targetURL := testBackendWithHandler(t, handler)

	target, err := NewReadOnlyTarget(targetURL, defaultTargetOptions)
	require.NoError(t, err)
	return target
}

func testTargetWithOptions(t testing.TB, targetOptions TargetOptions, handler http.HandlerFunc) *Target {
	t.Helper()

	_, targetURL := testBackendWithHandler(t, handler)

	target, err := NewTarget(targetURL, targetOptions)
	require.NoError(t, err)
	return target
}

func testRequestWithMatchedPrefix(req *http.Request, prefix string) *http.Request {
	ctx := context.WithValue(req.Context(), contextKeyRoutingContext, &routingContext{MatchedPrefix: prefix})
	return req.WithContext(ctx)
}

func testBackend(t testing.TB, body string, statusCode int) (*httptest.Server, string) {
	t.Helper()

	return testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(body))
	})
}

func testBackendWithHandler(t testing.TB, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	return server, serverURL.Host
}

// countingListener records how many connections a backend accepted, which is
// the only way to observe connection reuse from outside the transport.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}

	return conn, err
}

// testCountingBackend starts a backend that counts accepted connections. It
// cannot reuse testBackendWithHandler, as httptest.NewServer starts listening
// before there is any seam to wrap the listener in.
func testCountingBackend(t testing.TB, handler http.HandlerFunc) (*countingListener, string) {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	listener := &countingListener{Listener: server.Listener}
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	return listener, serverURL.Host
}

// testConfig returns a Config bound to ephemeral ports, carrying the same
// listener timeout defaults the run command ships.
func testConfig(t testing.TB) *Config {
	t.Helper()

	return &Config{
		Bind:               "127.0.0.1",
		HttpPort:           0,
		HttpsPort:          0,
		AlternateConfigDir: t.TempDir(),
		ReadHeaderTimeout:  DefaultReadHeaderTimeout,
		ReadTimeout:        DefaultReadTimeout,
		WriteTimeout:       DefaultWriteTimeout,
		IdleTimeout:        DefaultIdleTimeout,
	}
}

func testServer(t testing.TB, http3Enabled bool) *Server {
	t.Helper()

	config := testConfig(t)
	config.HTTP3Enabled = http3Enabled

	return testServerWithConfig(t, config)
}

func testServerWithConfig(t testing.TB, config *Config) *Server {
	t.Helper()

	router := NewRouter(config.StatePath())
	server := NewServer(config, router)
	err := server.Start()
	require.NoError(t, err)

	t.Cleanup(server.Stop)

	return server
}
