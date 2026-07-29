package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sync"
	"time"
)

const (
	StatusClientClosedRequest = 499
)

var (
	ErrorInvalidHostPattern = errors.New("invalid host pattern")
	ErrorDraining           = errors.New("target is draining")

	hostRegex = regexp.MustCompile(`^(\w[-_.\w+]+)(:\d+)?$`)
)

type TargetState int

const (
	TargetStateAdding TargetState = iota
	TargetStateDraining
	TargetStateHealthy
	TargetStateUnhealthy
)

func (ts TargetState) String() string {
	switch ts {
	case TargetStateAdding:
		return "adding"
	case TargetStateDraining:
		return "draining"
	case TargetStateHealthy:
		return "healthy"
	case TargetStateUnhealthy:
		return "unhealthy"
	}
	return ""
}

type TargetStateConsumer interface {
	TargetStateChanged(*Target)
}

type inflightRequest struct {
	cancel   context.CancelCauseFunc
	hijacked bool
}

type inflightMap map[*http.Request]*inflightRequest

type TargetOptions struct {
	HealthCheckConfig   HealthCheckConfig `json:"health_check_config"`
	ResponseTimeout     time.Duration     `json:"response_timeout"`
	BufferRequests      bool              `json:"buffer_requests"`
	BufferResponses     bool              `json:"buffer_responses"`
	MaxMemoryBufferSize int64             `json:"max_memory_buffer_size"`
	MaxRequestBodySize  int64             `json:"max_request_body_size"`
	MaxResponseBodySize int64             `json:"max_response_body_size"`
	LogRequestHeaders   []string          `json:"log_request_headers"`
	LogResponseHeaders  []string          `json:"log_response_headers"`
	ForwardHeaders      bool              `json:"forward_headers"`
	ScopeCookiePaths    bool              `json:"scope_cookie_paths"`

	// PathResponseTimeouts overrides ResponseTimeout for requests below a path
	// prefix. Each override needs its own transport, so keep the list short.
	PathResponseTimeouts []PathTimeout `json:"path_response_timeouts,omitempty"`
	// RequestTimeout bounds the whole request, not just the wait for response
	// headers. Zero (the default) leaves it unbounded.
	RequestTimeout time.Duration `json:"request_timeout,omitempty"`
	// PathRequestTimeouts overrides RequestTimeout for requests below a path
	// prefix.
	PathRequestTimeouts []PathTimeout `json:"path_request_timeouts,omitempty"`

	// RequestHeaderRules changes the headers the target receives, after the
	// X-Forwarded headers are set, so a rule has the last word over them.
	RequestHeaderRules HeaderRules `json:"request_header_rules,omitzero"`
	// ResponseHeaderRules changes the headers the client receives. It covers
	// responses the target produced; ones the proxy produced itself -- an error
	// page, a redirect, a 401 or a 429 -- never reach the target and so keep the
	// headers the proxy gave them.
	ResponseHeaderRules HeaderRules `json:"response_header_rules,omitzero"`

	// MaxConnsPerHost caps the connections -- dialing, active, and idle -- one of
	// this target's pools will open. Zero (the default) leaves it unlimited.
	// Requests over the cap queue rather than failing. Streaming responses hold a
	// slot until their body is closed; connections upgraded to another protocol
	// release theirs as soon as the upgrade completes, and so go uncounted for
	// the life of the stream.
	MaxConnsPerHost int `json:"max_conns_per_host,omitempty"`
	// MaxIdleConnsPerHost caps the idle connections kept for reuse. Zero means
	// the MaxIdleConnsPerHost default, not Go's much smaller one.
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`
	// IdleConnTimeout is how long an idle connection to this target is kept
	// before closing. Zero means DefaultTargetIdleConnTimeout, not "forever".
	IdleConnTimeout time.Duration `json:"idle_conn_timeout,omitempty"`
	// DialTimeout bounds establishing a connection to this target. Zero means
	// DefaultTargetDialTimeout, not "no limit".
	DialTimeout time.Duration `json:"dial_timeout,omitempty"`
	// DisableKeepAlives closes each connection after a single request. False
	// (the default) reuses connections.
	DisableKeepAlives bool `json:"disable_keep_alives,omitempty"`
}

func (to *TargetOptions) IsHealthCheckRequest(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && RoutedTargetPath(r) == to.HealthCheckConfig.Path
}

func (to *TargetOptions) normalizePathTimeouts() {
	to.PathResponseTimeouts = NormalizePathTimeouts(to.PathResponseTimeouts)
	to.PathRequestTimeouts = NormalizePathTimeouts(to.PathRequestTimeouts)
}

func (to *TargetOptions) canonicalizeLogHeaders() {
	for i, header := range to.LogRequestHeaders {
		to.LogRequestHeaders[i] = http.CanonicalHeaderKey(header)
	}
	for i, header := range to.LogResponseHeaders {
		to.LogResponseHeaders[i] = http.CanonicalHeaderKey(header)
	}
}

type pathProxyHandler struct {
	pathPrefix string
	handler    http.Handler
}

type Target struct {
	targetURL         *url.URL
	readonly          bool
	options           TargetOptions
	proxyHandler      http.Handler
	pathProxyHandlers []pathProxyHandler
	transports        []*http.Transport

	// weight is this target's share of its pool, and currentWeight the credit it
	// has accrued towards the next turn. Both are fork-only; see
	// target_weight.go, which owns every read and write of currentWeight.
	weight        int
	currentWeight int

	state        TargetState
	inflight     inflightMap
	inflightLock sync.Mutex

	healthcheck   *HealthCheck
	stateConsumer TargetStateConsumer
}

func NewTarget(targetURL string, options TargetOptions) (*Target, error) {
	host, weight, err := parseTargetSpec(targetURL)
	if err != nil {
		return nil, err
	}

	uri, err := parseTargetURL(host)
	if err != nil {
		return nil, err
	}

	options.canonicalizeLogHeaders()
	options.normalizePathTimeouts()

	target := &Target{
		targetURL: uri,
		options:   options,
		weight:    weight,

		state:    TargetStateAdding,
		inflight: inflightMap{},
	}

	target.proxyHandler = target.createProxyHandler(options.ResponseTimeout)

	// ResponseHeaderTimeout is a transport setting, so a per-path override needs
	// its own proxy handler (and therefore its own connection pool).
	for _, pathTimeout := range options.PathResponseTimeouts {
		target.pathProxyHandlers = append(target.pathProxyHandlers, pathProxyHandler{
			pathPrefix: pathTimeout.PathPrefix,
			handler:    target.createProxyHandler(pathTimeout.Timeout),
		})
	}

	return target, nil
}

func NewReadOnlyTarget(targetURL string, options TargetOptions) (*Target, error) {
	target, err := NewTarget(targetURL, options)
	if err == nil {
		target.readonly = true
	}

	return target, err
}

func (t *Target) Address() string {
	return t.targetURL.Host
}

func (t *Target) State() TargetState {
	t.inflightLock.Lock()
	defer t.inflightLock.Unlock()

	return t.state
}

func (t *Target) ReadOnly() bool {
	return t.readonly
}

func (t *Target) StartRequest(req *http.Request) (*http.Request, error) {
	t.inflightLock.Lock()
	defer t.inflightLock.Unlock()

	if t.state == TargetStateDraining {
		return nil, ErrorDraining
	}

	ctx, cancel := context.WithCancelCause(req.Context())
	req = req.WithContext(ctx)

	inflightRequest := &inflightRequest{cancel: cancel}
	t.inflight[req] = inflightRequest

	return req, nil
}

func (t *Target) SendRequest(w http.ResponseWriter, req *http.Request) {
	LoggingRequestContext(req).Target = t.Address()
	LoggingRequestContext(req).RequestHeaders = t.options.LogRequestHeaders
	LoggingRequestContext(req).ResponseHeaders = t.options.LogResponseHeaders

	inflightRequest := t.getInflightRequest(req)
	defer t.endInflightRequest(req)

	tw := newTargetResponseWriter(w, inflightRequest, t.cookieScope(req))
	t.handlerForRequest(req).ServeHTTP(tw, req)
}

func (t *Target) Drain(timeout time.Duration) {
	originalState := t.updateState(TargetStateDraining)
	if originalState == TargetStateDraining {
		return
	}
	defer t.updateState(originalState)

	deadline := time.After(timeout)
	toCancel := t.pendingRequestsToCancel()

	// Cancel any hijacked requests immediately, as they may be long-running.
	for _, inflight := range toCancel {
		if inflight.hijacked {
			inflight.cancel(ErrorDraining)
		}
	}

WAIT_FOR_REQUESTS_TO_COMPLETE:
	for req := range toCancel {
		select {
		case <-req.Context().Done():
		case <-deadline:
			break WAIT_FOR_REQUESTS_TO_COMPLETE
		}
	}

	// Cancel any remaining requests.
	for _, inflight := range toCancel {
		inflight.cancel(ErrorDraining)
	}
}

func (t *Target) BeginHealthChecks(stateConsumer TargetStateConsumer) {
	t.withInflightLock(func() {
		// Inside the lock: RecheckHealth reaches here while the previous prober's
		// goroutine can still be in HealthCheckCompleted reading this field.
		t.stateConsumer = stateConsumer

		if t.healthcheck != nil {
			t.healthcheck.Close()
		}

		healthCheckURL := t.buildHealthCheckURL()
		t.healthcheck = NewHealthCheck(
			t,
			healthCheckURL,
			t.options.HealthCheckConfig.Interval,
			t.options.HealthCheckConfig.Timeout,
			t.options.HealthCheckConfig.Host,
		)
	})
}

func (t *Target) StopHealthChecks() {
	t.withInflightLock(func() {
		if t.healthcheck != nil {
			t.healthcheck.Close()
			t.healthcheck = nil
		}
	})
}

// HealthCheckConsumer

func (t *Target) HealthCheckCompleted(success bool) {
	var previousState, newState TargetState
	var stateConsumer TargetStateConsumer

	t.withInflightLock(func() {
		previousState = t.state

		switch success {
		case true:
			switch t.state {
			case TargetStateAdding:
				t.state = TargetStateHealthy
			default:
				t.state = TargetStateHealthy
			}
		case false:
			switch t.state {
			case TargetStateHealthy:
				t.state = TargetStateUnhealthy
			}
		}

		newState = t.state

		// Read under the lock and used outside it: BeginHealthChecks writes this
		// field, and RecheckHealth calls it while this goroutine may be running.
		stateConsumer = t.stateConsumer
	})

	if newState != previousState {
		slog.Info("Target health updated", "target", t.Address(), "state", newState.String(), "was", previousState.String())

		if stateConsumer != nil {
			stateConsumer.TargetStateChanged(t)
		}
	}
}

// Private

func (t *Target) buildHealthCheckURL() *url.URL {
	healthCheckURL := *t.targetURL

	if t.options.HealthCheckConfig.Port > 0 {
		host, _, err := net.SplitHostPort(t.targetURL.Host)
		if err != nil {
			host = t.targetURL.Host
		}
		healthCheckURL.Host = fmt.Sprintf("%s:%d", host, t.options.HealthCheckConfig.Port)
	}

	return healthCheckURL.JoinPath(t.options.HealthCheckConfig.Path)
}

func (t *Target) createProxyHandler(responseTimeout time.Duration) http.Handler {
	bufferPool := NewBufferPool(ProxyBufferSize)

	// Retained so the per-path handlers' pools stay assertable: the buffering
	// middleware below replaces handler, leaving no way back to the transport.
	transport := newProxyTransport(t.options, responseTimeout)
	t.transports = append(t.transports, transport)

	var handler http.Handler = &httputil.ReverseProxy{
		BufferPool:     bufferPool,
		Rewrite:        t.rewrite,
		ModifyResponse: t.applyResponseHeaderRules,
		ErrorHandler:   t.handleProxyError,
		Transport:      transport,
	}

	if t.options.BufferResponses {
		handler = WithResponseBufferMiddleware(t.options.MaxMemoryBufferSize, t.options.MaxResponseBodySize, handler)
	}
	if t.options.BufferRequests {
		handler = WithRequestBufferMiddleware(t.options.MaxMemoryBufferSize, t.options.MaxRequestBodySize, handler)
	}

	return handler
}

// handlerForRequest returns the proxy handler carrying the response timeout
// that applies to this request's path.
func (t *Target) handlerForRequest(req *http.Request) http.Handler {
	for _, pathHandler := range t.pathProxyHandlers {
		if PathMatchesPrefix(req.URL.Path, pathHandler.pathPrefix) {
			return pathHandler.handler
		}
	}

	return t.proxyHandler
}

func (t *Target) rewrite(req *httputil.ProxyRequest) {
	t.forwardHeaders(req)

	req.SetURL(t.targetURL)
	req.Out.Host = req.In.Host

	req.Out.URL.Path = RoutedTargetPath(req.In)

	// Ensure query params are preserved exactly, including those we could not
	// parse.
	//
	// By default, httputil.ReverseProxy will drop unparseable query params to
	// guard against parameter smuggling attacks
	// (https://github.com/golang/go/issues/54663).
	//
	// One example of this is the use of semicolons in query params. Given a URL
	// like:
	//
	//   /path?p=a;b
	//
	// Some platforms interpret these params as equivalent to `p=a` and `b=`,
	// while others interpret it as a single query param: `p=a;b`. Because of this
	// confusion, Go's default behaviour is to drop the parameter entirely,
	// effectively turning our URL into just `/path`.
	//
	// However, any changes to the query params could break applications that
	// depend on them, so we should avoid doing this, and strive to be as
	// transparent as possible.
	//
	// In our case, we don't make any decisions based on the query params, so it's
	// safe for us to pass them through verbatim.
	req.Out.URL.RawQuery = req.In.URL.RawQuery

	// Last, so a rule can override a header the proxy itself decided on, such as
	// the X-Forwarded set above.
	t.options.RequestHeaderRules.apply(req.Out.Header)
}

// applyResponseHeaderRules runs as the proxy's ModifyResponse hook, which fires
// after ReverseProxy has stripped the hop-by-hop headers, so a rule's headers
// reach the client intact. It never fails: a rule that could not be applied
// would have been rejected when the service was deployed.
func (t *Target) applyResponseHeaderRules(res *http.Response) error {
	t.options.ResponseHeaderRules.apply(res.Header)
	return nil
}

func (t *Target) forwardHeaders(req *httputil.ProxyRequest) {
	if t.options.ForwardHeaders {
		req.Out.Header["X-Forwarded-For"] = req.In.Header["X-Forwarded-For"]
	}

	req.SetXForwarded()

	if t.options.ForwardHeaders {
		if req.In.Header.Get("X-Forwarded-Proto") != "" {
			req.Out.Header.Set("X-Forwarded-Proto", req.In.Header.Get("X-Forwarded-Proto"))
		}
		if req.In.Header.Get("X-Forwarded-Host") != "" {
			req.Out.Header.Set("X-Forwarded-Host", req.In.Header.Get("X-Forwarded-Host"))
		}
	}
}

func (t *Target) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	// A failure another target could still serve is recorded rather than
	// rendered, so no bytes reach the client before the retry.
	if attempt := proxyAttemptFromRequest(r); attempt != nil && t.isRetryableProxyError(err, r) {
		attempt.err = err
		return
	}

	if t.isRequestEntityTooLarge(err) {
		SetErrorResponse(w, r, http.StatusRequestEntityTooLarge, nil)
		return
	}

	if t.isGatewayTimeout(err) {
		SetErrorResponse(w, r, http.StatusGatewayTimeout, nil)
		return
	}

	if t.isRequestDeadlineExceeded(r) {
		slog.Info("Request cancelled by its deadline", "target", t.Address(), "path", r.URL.Path)
		SetErrorResponse(w, r, http.StatusGatewayTimeout, nil)
		return
	}

	if t.isClientCancellation(err) {
		// The client has disconnected so will not see the response, but we
		// still want to set it for the sake of the logs.
		w.WriteHeader(StatusClientClosedRequest)
		return
	}

	if t.isDraining(err) {
		slog.Info("Request cancelled due to draining", "target", t.Address(), "path", r.URL.Path)
		SetErrorResponse(w, r, http.StatusGatewayTimeout, nil)
		return
	}

	if isChunkedEncodingError(err) {
		slog.Info("Malformed request", "target", t.Address(), "path", r.URL.Path, "error", err)
		SetErrorResponse(w, r, http.StatusBadRequest, nil)
		return
	}

	slog.Error("Error while proxying", "target", t.Address(), "path", r.URL.Path, "error", err)
	SetErrorResponse(w, r, http.StatusBadGateway, nil)
}

func (t *Target) isRequestEntityTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func (t *Target) isGatewayTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// isRequestDeadlineExceeded distinguishes a request cancelled by its own
// deadline from one cancelled by the client: both surface as context.Canceled,
// so the cancellation cause on the request is what tells them apart.
func (t *Target) isRequestDeadlineExceeded(r *http.Request) bool {
	return errors.Is(context.Cause(r.Context()), ErrorRequestDeadlineExceeded)
}

func (t *Target) isClientCancellation(err error) bool {
	return errors.Is(err, context.Canceled)
}

func (t *Target) isDraining(err error) bool {
	return errors.Is(err, ErrorDraining)
}

func (t *Target) updateState(state TargetState) TargetState {
	t.inflightLock.Lock()
	defer t.inflightLock.Unlock()

	originalState := t.state
	t.state = state

	return originalState
}

func (t *Target) getInflightRequest(req *http.Request) *inflightRequest {
	t.inflightLock.Lock()
	defer t.inflightLock.Unlock()

	return t.inflight[req]
}

func (t *Target) endInflightRequest(req *http.Request) {
	t.inflightLock.Lock()
	defer t.inflightLock.Unlock()

	inflightRequest, ok := t.inflight[req]
	if ok {
		inflightRequest.cancel(nil)
		delete(t.inflight, req)
	}
}

func (t *Target) pendingRequestsToCancel() inflightMap {
	// We use a copy of the inflight map to iterate over while draining, so that
	// we don't need to lock it the whole time, which could interfere with the
	// locking that happens when requests end.
	t.inflightLock.Lock()
	defer t.inflightLock.Unlock()

	result := inflightMap{}
	maps.Copy(result, t.inflight)
	return result
}

func (t *Target) cookieScope(r *http.Request) *CookieScope {
	if !t.options.ScopeCookiePaths {
		return nil
	}

	routingContext := RoutingContext(r)
	if routingContext == nil || routingContext.MatchedPrefix == "" {
		return nil
	}

	return NewCookieScope(routingContext.MatchedPrefix, r.Host)
}

func (t *Target) withInflightLock(fn func()) {
	t.inflightLock.Lock()
	defer t.inflightLock.Unlock()

	fn()
}

func parseTargetURL(targetURL string) (*url.URL, error) {
	if !hostRegex.MatchString(targetURL) {
		return nil, fmt.Errorf("%s :%w", targetURL, ErrorInvalidHostPattern)
	}

	uri, _ := url.Parse("http://" + targetURL)
	return uri, nil
}

type targetResponseWriter struct {
	http.ResponseWriter
	header          http.Header
	headerWritten   bool
	inflightRequest *inflightRequest
	cookieScope     *CookieScope
}

func newTargetResponseWriter(w http.ResponseWriter, inflightRequest *inflightRequest, cookieScope *CookieScope) *targetResponseWriter {
	return &targetResponseWriter{
		ResponseWriter:  w,
		header:          http.Header{},
		headerWritten:   false,
		inflightRequest: inflightRequest,
		cookieScope:     cookieScope,
	}
}

func (w *targetResponseWriter) Header() http.Header {
	return w.header
}

func (w *targetResponseWriter) WriteHeader(statusCode int) {
	if w.cookieScope != nil {
		w.cookieScope.ApplyToHeader(w.header)
	}
	maps.Copy(w.ResponseWriter.Header(), w.header)

	w.ResponseWriter.WriteHeader(statusCode)
	w.headerWritten = true
}

func (w *targetResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(b)
}

func (w *targetResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ResponseWriter does not implement http.Hijacker")
	}

	w.inflightRequest.hijacked = true
	return hijacker.Hijack()
}

func (w *targetResponseWriter) Flush() {
	flusher, ok := w.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}
