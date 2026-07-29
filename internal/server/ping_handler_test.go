package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPingHandler_AnswersWithoutReachingTheProxy(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedBody   string
		reachesNext    bool
	}{
		{
			name:           "GET is answered",
			method:         http.MethodGet,
			path:           pingPath,
			expectedStatus: http.StatusOK,
			expectedBody:   pingBody,
		},
		{
			name:           "HEAD is answered without a body",
			method:         http.MethodHead,
			path:           pingPath,
			expectedStatus: http.StatusOK,
			expectedBody:   pingBody, // the recorder does not strip HEAD bodies; net/http does
		},
		{
			name:           "POST is rejected",
			method:         http.MethodPost,
			path:           pingPath,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "a trailing segment is not the ping path",
			method:         http.MethodGet,
			path:           pingPath + "/extra",
			expectedStatus: http.StatusTeapot,
			reachesNext:    true,
		},
		{
			name:           "an unrelated path reaches the proxy",
			method:         http.MethodGet,
			path:           "/",
			expectedStatus: http.StatusTeapot,
			reachesNext:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusTeapot)
			})

			w := httptest.NewRecorder()
			r := httptest.NewRequest(tt.method, tt.path, nil)
			WithPingMiddleware(next).ServeHTTP(w, r)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, tt.reachesNext, reached)

			if tt.expectedBody != "" {
				assert.Equal(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestPingHandler_IsNotCached(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, pingPath, nil)

	WithPingMiddleware(http.NotFoundHandler()).ServeHTTP(w, r)

	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
}

// The endpoint exists so a monitor can tell "proxy down" from "app down", which
// only works if it answers before anything is deployed.
func TestServer_PingAnsweredWithNoServicesDeployed(t *testing.T) {
	server := testServer(t, false)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d%s", server.HttpPort(), pingPath))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, pingBody, string(body))
}

// A monitor hits this every few seconds forever, so it must not fill the access
// log. The mount point in buildHandler is what guarantees it; this pins that
// ordering so a later reshuffle cannot quietly undo it.
func TestServer_PingIsNotAccessLogged(t *testing.T) {
	out := &syncBuffer{}
	previous := slog.Default()
	// buildHandler captures slog.Default() when the server starts, so swap it
	// before testServer and put it back afterwards.
	slog.SetDefault(slog.New(slog.NewJSONHandler(out, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	server := testServer(t, false)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d%s", server.HttpPort(), pingPath))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.NotContains(t, out.String(), pingPath)

	// A request that is routed normally still gets logged, so the assertion
	// above is about the ping path and not about logging being off entirely.
	resp, err = http.Get(fmt.Sprintf("http://localhost:%d/not-ping", server.HttpPort()))
	require.NoError(t, err)
	resp.Body.Close()

	assert.Contains(t, out.String(), "/not-ping")
}

// syncBuffer collects log output that request goroutines are still writing while
// the test reads it. slog serialises its own writes; this covers the read side.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A deployed service owns every path on its hosts; the reserved namespace is the
// exception, and it has to hold over TLS too.
func TestServer_PingNotRoutedToADeployedService(t *testing.T) {
	// Health checks hit the same backend, so only answer 418 off the probe path.
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultHealthCheckPath {
			w.WriteHeader(http.StatusTeapot)
		}
	})
	server := testServer(t, false)

	certPath, keyPath := prepareTestCertificateFiles(t)
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"localhost"}
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSCertificatePath = certPath
	serviceOptions.TLSPrivateKeyPath = keyPath

	testDeployTarget(t, target, server, serviceOptions)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://localhost:%d%s", server.HttpsPort(), pingPath))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, pingBody, string(body))

	// The service is still serving everything else on that host.
	resp, err = client.Get(fmt.Sprintf("https://localhost:%d/", server.HttpsPort()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
}
