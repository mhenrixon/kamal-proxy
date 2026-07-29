package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// fallbackDockerAPIVersion is used when /version cannot be read. Hardened
	// socket proxies routinely allow the container endpoints while denying
	// /version, so failing to negotiate must not stop the client working. 1.41
	// ships with Docker 20.10 and is old enough that any daemon we could
	// plausibly be talking to accepts it.
	fallbackDockerAPIVersion = "1.41"

	// maxDockerErrorBodyBytes caps how much of a failure response reaches the
	// error string, which travels to the operator's terminal over net/rpc.
	maxDockerErrorBodyBytes = 4 << 10

	// maxDockerVersionBodyBytes is deliberately far larger: /version on a
	// plugin-heavy host carries a Components array listing every plugin, and
	// truncating that JSON turns a healthy daemon into a parse failure that
	// silently drops the client to the fallback version.
	maxDockerVersionBodyBytes = 1 << 20

	dockerRequestTimeout = 30 * time.Second

	// defaultDockerStopTimeout is what a stop with no caller deadline asks the
	// daemon for. It matches Docker's own default so behaviour is unchanged for
	// containers that never configured one.
	defaultDockerStopTimeout = 10 * time.Second

	// dockerStopMargin keeps the daemon's SIGKILL strictly inside our budget, so
	// the response arrives before our context expires rather than racing it.
	dockerStopMargin = 5 * time.Second
)

// DockerClient talks to the Docker daemon over its unix socket. It implements
// ContainerLifecycle with no external dependency: the Engine API calls it needs
// are three endpoints, and pulling in the official SDK for them would add a
// large dependency tree to a proxy that otherwise has none.
//
// Reaching this socket is root-equivalent on the host. It is only constructed
// when the operator passes --docker-socket.
type DockerClient struct {
	socketPath string
	http       *http.Client

	lock       sync.Mutex
	apiVersion string
}

func NewDockerClient(socketPath string) *DockerClient {
	return &DockerClient{
		socketPath: socketPath,
		http: &http.Client{
			Timeout: dockerRequestTimeout,

			// Docker's router cleans the decoded path and answers 301 to the
			// canonical form, and Go rewrites a redirected POST as a GET. Following
			// that would turn a start into a read: ContainerExists would pass on a
			// reference StartContainer can never start, so the deploy preflight
			// would accept exactly what it exists to reject. Against a redirecting
			// socket proxy a stop could report success having stopped nothing.
			// Nothing in the Engine API legitimately redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},

			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *DockerClient) StartContainer(ctx context.Context, ref string) error {
	return c.send(ctx, http.MethodPost, c.containerPath(ctx, ref, "start"), ref)
}

// StopContainer stops the container, telling the daemon how long to wait between
// SIGTERM and SIGKILL rather than letting the container's own StopTimeout decide.
//
// Without that, the two deadlines are independent and the daemon's is the one we
// cannot see: kamal passes `options:` straight through to `docker run`, so a
// container created with --stop-timeout 60 keeps the daemon working long after
// our context expires. We would report a failure for a stop the daemon then
// completes, and the controller would roll the service back to active and put
// its targets back for a container Docker is about to kill.
func (c *DockerClient) StopContainer(ctx context.Context, ref string) error {
	path := c.containerPath(ctx, ref, "stop") + "?t=" + strconv.Itoa(stopTimeoutSeconds(ctx))
	return c.send(ctx, http.MethodPost, path, ref)
}

// stopTimeoutSeconds leaves the daemon a kill deadline that lands inside our own
// budget, with a margin for the round trip. A caller with no deadline still gets
// a bound: an unbounded stop is what this exists to prevent.
func stopTimeoutSeconds(ctx context.Context) int {
	deadline, ok := ctx.Deadline()
	if !ok {
		return int(defaultDockerStopTimeout.Seconds())
	}

	remaining := time.Until(deadline) - dockerStopMargin
	if remaining < time.Second {
		// Already out of budget. One second still beats zero, which Docker reads
		// as "SIGKILL immediately" and denies the app any chance to shut down.
		return 1
	}

	return int(remaining.Seconds())
}

// ContainerExists inspects the container so a deploy can reject a reference that
// would otherwise only fail hours later at the first idle timeout.
func (c *DockerClient) ContainerExists(ctx context.Context, ref string) error {
	return c.send(ctx, http.MethodGet, c.containerPath(ctx, ref, "json"), ref)
}

func (c *DockerClient) send(ctx context.Context, method, path, ref string) error {
	resp, err := c.do(ctx, method, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return c.classify(resp, ref)
}

// containerPath builds /v<version>/containers/<ref>/<action>. The reference is
// path-escaped because a container name is operator-supplied and a bare name
// with a slash would otherwise change which endpoint is addressed.
func (c *DockerClient) containerPath(ctx context.Context, ref, action string) string {
	return fmt.Sprintf("/v%s/containers/%s/%s", c.negotiateAPIVersion(ctx), url.PathEscape(ref), action)
}

func (c *DockerClient) do(ctx context.Context, method, path string) (*http.Response, error) {
	// The host is ignored -- the transport always dials the socket -- but the URL
	// still needs one to be well formed.
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker socket %s: %w", c.socketPath, err)
	}

	return resp, nil
}

// classify turns a response into the sentinel errors the preflight and the wake
// path branch on.
func (c *DockerClient) classify(resp *http.Response, ref string) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil

	// Already in the requested state. Starting a running container or stopping a
	// stopped one is exactly what a coalesced wake or a redundant sleep does, and
	// neither is a failure.
	case resp.StatusCode == http.StatusNotModified:
		return nil

	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrContainerNotFound, ref)

	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrContainerInspectForbidden, ref)

	default:
		return fmt.Errorf("docker returned %s for container %s: %s",
			resp.Status, ref, readLimited(resp.Body, maxDockerErrorBodyBytes))
	}
}

// negotiateAPIVersion asks the daemon which API version it speaks, caching only
// a successful answer. Caching a failure would pin the client to the fallback
// for the life of the process even after the daemon came back.
func (c *DockerClient) negotiateAPIVersion(ctx context.Context) string {
	c.lock.Lock()
	cached := c.apiVersion
	c.lock.Unlock()

	if cached != "" {
		return cached
	}

	version := c.readAPIVersion(ctx)
	if version == "" {
		return fallbackDockerAPIVersion
	}

	c.lock.Lock()
	c.apiVersion = version
	c.lock.Unlock()

	return version
}

// readAPIVersion returns "" for every failure mode -- unreachable socket, denied
// endpoint, non-JSON body, JSON without the field -- so the caller has a single
// fallback path rather than four.
func (c *DockerClient) readAPIVersion(ctx context.Context) string {
	resp, err := c.do(ctx, http.MethodGet, "/version")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	var payload struct {
		APIVersion string `json:"ApiVersion"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDockerVersionBodyBytes)).Decode(&payload); err != nil {
		return ""
	}

	return payload.APIVersion
}

func readLimited(r io.Reader, limit int64) string {
	body, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(body))
}
