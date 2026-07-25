package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Deploying(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
	server := testServer(t, true)

	testDeployTarget(t, target, server, defaultServiceOptions)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/", server.HttpPort()))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_DeployingHTTPS(t *testing.T) {
	startDeployment := func(http3Enabled bool) *Server {
		target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
		server := testServer(t, http3Enabled)

		certPath, keyPath := prepareTestCertificateFiles(t)
		serviceOptions := defaultServiceOptions
		serviceOptions.Hosts = []string{"localhost"}
		serviceOptions.TLSEnabled = true
		serviceOptions.TLSCertificatePath = certPath
		serviceOptions.TLSPrivateKeyPath = keyPath
		serviceOptions.TLSRedirect = true

		testDeployTarget(t, target, server, serviceOptions)
		return server
	}

	t.Run("with HTTP/3 enabled", func(t *testing.T) {
		server := startDeployment(true)

		t.Run("http/1.1", func(t *testing.T) {
			resp, err := testRequestUsingHTTP11(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/1.1", resp.Proto)

			assert.Contains(t, resp.Header.Get("Alt-Svc"), "h3")
			assert.Contains(t, resp.Header.Get("Alt-Svc"), fmt.Sprintf(":%d", server.HttpsPort()))
		})

		t.Run("http/2", func(t *testing.T) {
			resp, err := testRequestUsingHTTP2(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/2.0", resp.Proto)

			assert.Contains(t, resp.Header.Get("Alt-Svc"), "h3")
			assert.Contains(t, resp.Header.Get("Alt-Svc"), fmt.Sprintf(":%d", server.HttpsPort()))
		})

		t.Run("http/3", func(t *testing.T) {
			resp, err := testRequestUsingHTTP3(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/3.0", resp.Proto)

			assert.Empty(t, resp.Header.Get("Alt-Svc"))
		})
	})

	t.Run("with HTTP/3 disabled", func(t *testing.T) {
		server := startDeployment(false)

		t.Run("http/1.1", func(t *testing.T) {
			resp, err := testRequestUsingHTTP11(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/1.1", resp.Proto)

			assert.Empty(t, resp.Header.Get("Alt-Svc"))
		})

		t.Run("http/2", func(t *testing.T) {
			resp, err := testRequestUsingHTTP2(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/2.0", resp.Proto)

			assert.Empty(t, resp.Header.Get("Alt-Svc"))
		})

		t.Run("http/3", func(t *testing.T) {
			// Ensure we don't already have a UDP listener for HTTP/3
			addr := fmt.Sprintf(":%d", server.HttpsPort())
			con, err := net.ListenPacket("udp", addr)
			require.NoError(t, err)
			con.Close()
		})
	})
}

func TestServer_StopAllowsInflightRequestsToComplete(t *testing.T) {
	// Health checks also hit the backend, so gate on a path they don't use.
	handlerStarted := make(chan struct{})
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(handlerStarted)
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	})

	config := testConfig(t)
	router := NewRouter(config.StatePath())
	server := NewServer(config, router)
	require.NoError(t, server.Start())

	testDeployTarget(t, target, server, defaultServiceOptions)

	responses := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/slow", server.HttpPort()))
		if err == nil {
			responses <- resp
		}
		close(responses)
	}()

	<-handlerStarted
	server.Stop()

	resp, ok := <-responses
	require.True(t, ok, "in-flight request should have completed during shutdown")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_StopRespectsConfiguredShutdownTimeout(t *testing.T) {
	// Health checks also hit the backend, so gate on a path they don't use.
	handlerStarted := make(chan struct{})
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(handlerStarted)
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
	})

	config := testConfig(t)
	config.ShutdownTimeout = 250 * time.Millisecond
	router := NewRouter(config.StatePath())
	server := NewServer(config, router)
	require.NoError(t, server.Start())

	testDeployTarget(t, target, server, defaultServiceOptions)

	go func() {
		_, _ = http.Get(fmt.Sprintf("http://127.0.0.1:%d/slow", server.HttpPort()))
	}()

	<-handlerStarted

	started := time.Now()
	server.Stop()

	assert.Less(t, time.Since(started), 3*time.Second, "Stop should be bounded by the configured shutdown timeout")
}

func TestServer_ReusePortAllowsOverlappingGenerations(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("SO_REUSEPORT is not supported on this platform")
	}

	configA := testConfig(t)
	configA.ReusePort = true
	serverA := testServerWithConfig(t, configA)
	testDeployTarget(t, testTarget(t, func(w http.ResponseWriter, r *http.Request) {}), serverA, defaultServiceOptions)

	// A second generation binds the same ports while the first still serves.
	configB := testConfig(t)
	configB.ReusePort = true
	configB.HttpPort = serverA.HttpPort()
	configB.HttpsPort = serverA.HttpsPort()

	routerB := NewRouter(configB.StatePath())
	serverB := NewServer(configB, routerB)
	require.NoError(t, serverB.Start())
	t.Cleanup(serverB.Stop)

	testDeployTarget(t, testTarget(t, func(w http.ResponseWriter, r *http.Request) {}), serverB, defaultServiceOptions)

	// Whichever generation the kernel picks, requests keep succeeding.
	for range 5 {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", serverA.HttpPort()))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func TestServer_DrainHandsOffToOverlappingGeneration(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("SO_REUSEPORT is not supported on this platform")
	}

	// Old generation, serving a slow request when the drain starts.
	handlerStarted := make(chan struct{})
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(handlerStarted)
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	})

	configA := testConfig(t)
	configA.ReusePort = true
	routerA := NewRouter(configA.StatePath())
	serverA := NewServer(configA, routerA)
	require.NoError(t, serverA.Start())
	t.Cleanup(serverA.Stop)

	testDeployTarget(t, target, serverA, defaultServiceOptions)

	// New generation restores the old generation's state from the shared
	// data dir and binds the same ports before the old one leaves.
	configB := testConfig(t)
	configB.ReusePort = true
	configB.AlternateConfigDir = configA.AlternateConfigDir
	configB.HttpPort = serverA.HttpPort()
	configB.HttpsPort = serverA.HttpsPort()

	routerB := NewRouter(configB.StatePath())
	require.NoError(t, routerB.RestoreLastSavedState())
	serverB := NewServer(configB, routerB)
	require.NoError(t, serverB.Start())
	t.Cleanup(serverB.Stop)

	responses := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/slow", serverA.HttpPort()))
		if err == nil {
			responses <- resp
		}
		close(responses)
	}()
	<-handlerStarted

	require.NoError(t, serverA.BeginDrain(5*time.Second))

	// The in-flight request on the draining generation completed.
	resp, ok := <-responses
	require.True(t, ok, "in-flight request should complete during the drain")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The new generation keeps serving the shared ports.
	for range 5 {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", serverA.HttpPort()))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// The drain signalled shutdown and flushed state.
	select {
	case <-serverA.ShutdownRequested():
	case <-time.After(2 * time.Second):
		t.Fatal("expected ShutdownRequested to be signalled after drain")
	}

	f, err := os.Open(configA.StatePath())
	require.NoError(t, err)
	defer f.Close()
	var services []*Service
	require.NoError(t, json.NewDecoder(f).Decode(&services))
	require.Len(t, services, 1)
}

func TestCommandHandler_DrainRepliesAfterDrainCompletes(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})

	config := testConfig(t)
	router := NewRouter(config.StatePath())
	server := NewServer(config, router)
	require.NoError(t, server.Start())
	t.Cleanup(server.Stop)

	testDeployTarget(t, target, server, defaultServiceOptions)

	var reply bool
	require.NoError(t, server.commandHandler.Drain(DrainArgs{Timeout: time.Second}, &reply))
	assert.True(t, reply)

	select {
	case <-server.ShutdownRequested():
	case <-time.After(2 * time.Second):
		t.Fatal("expected ShutdownRequested after Drain RPC")
	}
}

func TestServer_WithoutReusePortSecondBindFails(t *testing.T) {
	serverA := testServer(t, false)

	configB := testConfig(t)
	configB.HttpPort = serverA.HttpPort()
	configB.HttpsPort = serverA.HttpsPort()

	serverB := NewServer(configB, NewRouter(configB.StatePath()))
	require.Error(t, serverB.Start())
}

func TestServer_SavesStateOnStop(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})

	config := testConfig(t)
	router := NewRouter(config.StatePath())
	server := NewServer(config, router)
	require.NoError(t, server.Start())

	testDeployTarget(t, target, server, defaultServiceOptions)

	// Remove the state file the deploy wrote, to prove Stop rewrites it.
	require.NoError(t, os.Remove(config.StatePath()))

	server.Stop()

	f, err := os.Open(config.StatePath())
	require.NoError(t, err)
	defer f.Close()

	var services []*Service
	require.NoError(t, json.NewDecoder(f).Decode(&services))
	require.Len(t, services, 1)
}

// Helpers

func testDeployTarget(tb testing.TB, target *Target, server *Server, serviceOptions ServiceOptions) {
	tb.Helper()
	var result bool
	err := server.commandHandler.Deploy(DeployArgs{
		TargetURLs:        []string{target.Address()},
		DeploymentOptions: defaultDeploymentOptions,
		ServiceOptions:    serviceOptions,
		TargetOptions:     defaultTargetOptions,
	}, &result)

	require.NoError(tb, err)
}

func testRequestUsingHTTP11(tb testing.TB, server *Server) (*http.Response, error) {
	tb.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return testRequestUsingTransport(server, transport)
}

func testRequestUsingHTTP2(tb testing.TB, server *Server) (*http.Response, error) {
	tb.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}

	return testRequestUsingTransport(server, transport)
}

func testRequestUsingHTTP3(tb testing.TB, server *Server) (*http.Response, error) {
	tb.Helper()
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
	}
	tb.Cleanup(func() { _ = transport.Close() })

	return testRequestUsingTransport(server, transport)
}

func testRequestUsingTransport(server *Server, transport http.RoundTripper) (*http.Response, error) {
	client := &http.Client{
		Transport: transport,
	}

	uri := fmt.Sprintf("https://localhost:%d/", server.HttpsPort())
	return client.Get(uri)
}
