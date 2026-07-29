package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDockerDaemon serves a handler on a real unix socket, so the client is
// exercised over the same transport it uses in production rather than a stub.
func testDockerDaemon(t *testing.T, handler http.HandlerFunc) (*DockerClient, *recordedRequests) {
	t.Helper()

	// macOS caps sun_path at 104 bytes and t.TempDir() paths are long, so the
	// socket goes somewhere short rather than in the test's own temp dir.
	dir, err := os.MkdirTemp("", "kp")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "d.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	recorded := &recordedRequests{}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RequestURI, not URL.Path: Go hands the handler a decoded path, so
		// asserting on that cannot tell an escaped reference from an unescaped one.
		recorded.add(r.Method + " " + r.RequestURI)
		handler(w, r)
	})}

	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })

	return NewDockerClient(socketPath), recorded
}

type recordedRequests struct {
	mu    sync.Mutex
	paths []string
}

func (r *recordedRequests) add(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, path)
}

func (r *recordedRequests) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.paths...)
}

func TestDockerClient_NegotiatesAndUsesVersionedPaths(t *testing.T) {
	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	require.NoError(t, client.StartContainer(context.Background(), "web-1"))

	assert.Equal(t, []string{"GET /version", "POST /v1.44/containers/web-1/start"}, recorded.all())

	// The version is negotiated once and reused.
	require.NoError(t, client.StopContainer(context.Background(), "web-1"))
	assert.Equal(t, []string{
		"GET /version",
		"POST /v1.44/containers/web-1/start",
		"POST /v1.44/containers/web-1/stop?t=10",
	}, recorded.all())
}

func TestDockerClient_PathEscapesTheContainerReference(t *testing.T) {
	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	require.NoError(t, client.StartContainer(context.Background(), "we/ird name"))

	assert.Contains(t, recorded.all(), "POST /v1.44/containers/we%2Fird%20name/start",
		"an unescaped slash would change which endpoint is addressed")
}

// Starting an already-running container answers 304. That is what lets a wake
// coalesced behind another wake succeed, and what lets a proxy whose state file
// said "sleeping" for a container that never stopped heal itself.
func TestDockerClient_TreatsNotModifiedAsSuccess(t *testing.T) {
	client, _ := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	})

	assert.NoError(t, client.StartContainer(context.Background(), "web-1"))
	assert.NoError(t, client.StopContainer(context.Background(), "web-1"))
}

func TestDockerClient_FallsBackWhenVersionIsUnavailable(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			// A hardened socket proxy that allows start/stop but not /version.
			name: "version endpoint forbidden",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/version" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			},
		},
		{
			name: "version payload is not JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/version" {
					fmt.Fprint(w, "<html>nope</html>")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			},
		},
		{
			name: "version payload omits ApiVersion",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/version" {
					fmt.Fprint(w, `{"Os":"linux"}`)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, recorded := testDockerDaemon(t, tt.handler)

			require.NoError(t, client.StartContainer(context.Background(), "web-1"))

			assert.Contains(t, recorded.all(), "POST /v"+fallbackDockerAPIVersion+"/containers/web-1/start",
				"an unusable /version must not stop the client working")
		})
	}
}

// Caching a negotiation failure would pin the client to the fallback version for
// the life of the process, even after the daemon came back.
func TestDockerClient_DoesNotCacheANegotiationFailure(t *testing.T) {
	var versionCalls atomic.Int64

	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			if versionCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	require.NoError(t, client.StartContainer(context.Background(), "web-1"))
	require.NoError(t, client.StartContainer(context.Background(), "web-1"))

	assert.Equal(t, int64(2), versionCalls.Load(), "a failed negotiation must be retried")
	assert.Contains(t, recorded.all(), "POST /v"+fallbackDockerAPIVersion+"/containers/web-1/start")
	assert.Contains(t, recorded.all(), "POST /v1.44/containers/web-1/start")
}

func TestDockerClient_ClassifiesMissingAndForbidden(t *testing.T) {
	tests := []struct {
		status   int
		expected error
	}{
		{status: http.StatusNotFound, expected: ErrContainerNotFound},
		{status: http.StatusForbidden, expected: ErrContainerInspectForbidden},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.status), func(t *testing.T) {
			client, _ := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/version" {
					fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
					return
				}
				w.WriteHeader(tt.status)
			})

			require.ErrorIs(t, client.ContainerExists(context.Background(), "web-1"), tt.expected)
			require.ErrorIs(t, client.StartContainer(context.Background(), "web-1"), tt.expected)
		})
	}
}

func TestDockerClient_ContainerExistsAcceptsAKnownContainer(t *testing.T) {
	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		fmt.Fprint(w, `{"Id":"deadbeef"}`)
	})

	require.NoError(t, client.ContainerExists(context.Background(), "web-1"))
	assert.Contains(t, recorded.all(), "GET /v1.44/containers/web-1/json")
}

func TestDockerClient_TruncatesLongErrorBodies(t *testing.T) {
	client, _ := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, strings.Repeat("x", 64*1024))
	})

	err := client.StartContainer(context.Background(), "web-1")
	require.Error(t, err)
	assert.Less(t, len(err.Error()), maxDockerErrorBodyBytes+512,
		"a daemon returning a huge body must not put all of it in the error")
}

// A plugin-heavy host's /version payload is far larger than an error body, and
// capping both at the same size truncates the JSON into a parse failure -- which
// would silently drop the client to the fallback version on a healthy daemon.
func TestDockerClient_ReadsALargeVersionPayload(t *testing.T) {
	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"Padding":%q,"ApiVersion":"1.44"}`, strings.Repeat("p", 32*1024))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	require.NoError(t, client.StartContainer(context.Background(), "web-1"))
	assert.Contains(t, recorded.all(), "POST /v1.44/containers/web-1/start",
		"a large but valid /version payload must still negotiate")
}

func TestDockerClient_SurfacesAnUnreachableSocket(t *testing.T) {
	client := NewDockerClient(filepath.Join(t.TempDir(), "absent.sock"))

	err := client.StartContainer(context.Background(), "web-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrContainerNotFound,
		"a dead socket is not the same as a missing container")
}

func TestDockerClient_RespectsContextCancellation(t *testing.T) {
	client, _ := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.StartContainer(ctx, "web-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
}

// Docker's own SIGTERM-to-SIGKILL wait comes from the container's StopTimeout,
// which the proxy cannot see -- kamal passes `options:` straight through to
// docker run, and compose has stop_grace_period. Left unbounded, a container
// configured to wait longer than our budget makes the client give up on a stop
// the daemon then completes: the controller rolls back to active and puts the
// targets back for a container Docker is about to kill.
func TestDockerClient_BoundsTheDaemonStopInsideTheCallersDeadline(t *testing.T) {
	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, client.StopContainer(ctx, "web-1"))

	var stopPath string
	for _, p := range recorded.all() {
		if strings.Contains(p, "/stop") {
			stopPath = p
		}
	}
	require.NotEmpty(t, stopPath)

	seconds := stopTimeoutFromPath(t, stopPath)
	assert.Positive(t, seconds, "the daemon needs a kill deadline")
	assert.Less(t, seconds, 30, "it has to land inside our own budget, not on it")
}

func TestDockerClient_StopWithoutADeadlineStillBoundsTheDaemon(t *testing.T) {
	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	require.NoError(t, client.StopContainer(context.Background(), "web-1"))

	var stopPath string
	for _, p := range recorded.all() {
		if strings.Contains(p, "/stop") {
			stopPath = p
		}
	}
	assert.Positive(t, stopTimeoutFromPath(t, stopPath))
}

func stopTimeoutFromPath(t *testing.T, path string) int {
	t.Helper()

	_, query, found := strings.Cut(path, "?")
	require.True(t, found, "stop must carry a timeout: %s", path)

	values, err := url.ParseQuery(query)
	require.NoError(t, err)

	seconds, err := strconv.Atoi(values.Get("t"))
	require.NoError(t, err, "t must be an integer: %s", path)
	return seconds
}

// Docker's router cleans the decoded path and answers 301 to the canonical form,
// and Go rewrites a redirected POST as a GET. Following that turns a start into
// a read: ContainerExists passes on a reference StartContainer can never start,
// so the deploy preflight accepts exactly what it exists to reject. Against a
// redirecting socket proxy a stop could even report success having stopped
// nothing. Nothing in the Engine API legitimately redirects.
func TestDockerClient_DoesNotFollowRedirects(t *testing.T) {
	client, recorded := testDockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"ApiVersion":"1.44"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/start") || strings.HasSuffix(r.URL.Path, "/stop") {
			http.Redirect(w, r, "/ok", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.StartContainer(context.Background(), "web-1")
	require.Error(t, err, "a redirect must not be silently re-issued as a GET")

	for _, p := range recorded.all() {
		assert.NotContains(t, p, "/ok", "the client must not have followed the redirect")
	}
}
