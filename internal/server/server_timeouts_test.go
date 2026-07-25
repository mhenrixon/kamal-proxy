package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_ClosesSlowHeaderConnections(t *testing.T) {
	config := testConfig(t)
	config.ReadHeaderTimeout = 250 * time.Millisecond
	server := testServerWithConfig(t, config)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.HttpPort()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	// Open a request and dribble headers without ever terminating them, the
	// classic slowloris pattern.
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	start := time.Now()
	_, err = io.ReadAll(conn)
	elapsed := time.Since(start)

	// The server must cut the connection off itself rather than leaving us to
	// hit our own read deadline.
	require.False(t, isTimeout(err), "connection was still open after ReadHeaderTimeout: %v", err)
	assert.Less(t, elapsed, 2*time.Second, "connection outlived ReadHeaderTimeout")
}

func TestServer_KeepsHeaderConnectionsOpenWithinTimeout(t *testing.T) {
	config := testConfig(t)
	config.ReadHeaderTimeout = 3 * time.Second
	server := testServerWithConfig(t, config)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.HttpPort()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"))
	require.NoError(t, err)

	// Well inside ReadHeaderTimeout the connection must still be usable, so a
	// short read blocks rather than returning EOF.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(250*time.Millisecond)))

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	require.Error(t, err)
	assert.True(t, isTimeout(err), "connection closed before ReadHeaderTimeout: %v", err)
}

func TestServer_AppliesConfiguredTimeoutsToEveryListener(t *testing.T) {
	config := testConfig(t)
	config.ReadHeaderTimeout = 11 * time.Second
	config.ReadTimeout = 22 * time.Second
	config.WriteTimeout = 33 * time.Second
	config.IdleTimeout = 44 * time.Second
	config.MetricsPort = findFreePort(t)

	server := testServerWithConfig(t, config)

	listeners := map[string]*http.Server{
		"http":    server.httpServer,
		"https":   server.httpsServer,
		"metrics": server.metricsServer,
	}

	for name, httpServer := range listeners {
		t.Run(name, func(t *testing.T) {
			require.NotNil(t, httpServer)
			assert.Equal(t, 11*time.Second, httpServer.ReadHeaderTimeout)
			assert.Equal(t, 22*time.Second, httpServer.ReadTimeout)
			assert.Equal(t, 33*time.Second, httpServer.WriteTimeout)
			assert.Equal(t, 44*time.Second, httpServer.IdleTimeout)
		})
	}
}

func TestServer_AppliesIdleTimeoutToHTTP3(t *testing.T) {
	config := testConfig(t)
	config.HTTP3Enabled = true
	config.IdleTimeout = 44 * time.Second

	server := testServerWithConfig(t, config)

	require.NotNil(t, server.http3Server)
	assert.Equal(t, 44*time.Second, server.http3Server.IdleTimeout)
}

func TestConfig_TimeoutDefaults(t *testing.T) {
	tests := []struct {
		name    string
		actual  time.Duration
		nonZero bool
		reason  string
	}{
		{
			name:    "read header timeout bounds slow header attacks",
			actual:  DefaultReadHeaderTimeout,
			nonZero: true,
		},
		{
			name:    "idle timeout bounds idle keep-alive connections",
			actual:  DefaultIdleTimeout,
			nonZero: true,
		},
		{
			name:    "read timeout stays disabled so long uploads are not truncated",
			actual:  DefaultReadTimeout,
			nonZero: false,
		},
		{
			name:    "write timeout stays disabled so SSE and streaming are not truncated",
			actual:  DefaultWriteTimeout,
			nonZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.nonZero {
				assert.Positive(t, tt.actual)
			} else {
				assert.Zero(t, tt.actual)
			}
		})
	}
}

// Helpers

// isTimeout reports whether err is our own client-side read deadline firing,
// which means the server left the connection open.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func findFreePort(t testing.TB) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	return port
}
