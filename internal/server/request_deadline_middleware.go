package server

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrorRequestDeadlineExceeded is the cancellation cause used when a request
// outlives its whole-request deadline. Target.handleProxyError maps it to a
// gateway timeout rather than a client cancellation.
var ErrorRequestDeadlineExceeded = errors.New("request deadline exceeded")

// RequestDeadlineMiddleware bounds the total time a request may take, including
// the time spent streaming the response body -- unlike the target's response
// timeout, which only bounds the wait for response headers.
//
// Streaming responses are exempt: WebSocket upgrades and event-stream requests
// are recognized before proxying, and a response that turns out to be a stream
// stops the deadline before it can truncate it.
type RequestDeadlineMiddleware struct {
	timeout      time.Duration
	pathTimeouts []PathTimeout
	next         http.Handler
}

func WithRequestDeadlineMiddleware(timeout time.Duration, pathTimeouts []PathTimeout, next http.Handler) http.Handler {
	return &RequestDeadlineMiddleware{
		timeout:      timeout,
		pathTimeouts: pathTimeouts,
		next:         next,
	}
}

func (h *RequestDeadlineMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	timeout := ResolvePathTimeout(r.URL.Path, h.pathTimeouts, h.timeout)
	if timeout <= 0 || isStreamingRequest(r) {
		h.next.ServeHTTP(w, r)
		return
	}

	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)

	timer := time.AfterFunc(timeout, func() {
		slog.Warn("Request exceeded its deadline", "path", r.URL.Path, "timeout", timeout)
		cancel(ErrorRequestDeadlineExceeded)
	})
	defer timer.Stop()

	deadlineWriter := &deadlineResponseWriter{ResponseWriter: w, stopDeadline: func() { timer.Stop() }}

	h.next.ServeHTTP(deadlineWriter, r.WithContext(ctx))
}

// isStreamingRequest reports whether the request itself announces that its
// response will be long-lived, which a whole-request deadline must not truncate.
func isStreamingRequest(r *http.Request) bool {
	if isWebSocketRequest(r) {
		return true
	}

	for _, accept := range r.Header.Values("Accept") {
		if strings.Contains(strings.ToLower(accept), "text/event-stream") {
			return true
		}
	}

	return false
}

// deadlineResponseWriter stops the deadline as soon as the response reveals
// itself to be a stream, mirroring the streaming bypass in
// ResponseBufferMiddleware.
type deadlineResponseWriter struct {
	http.ResponseWriter
	stopDeadline  func()
	headerWritten bool
}

func (w *deadlineResponseWriter) WriteHeader(statusCode int) {
	if !w.headerWritten {
		w.headerWritten = true

		if w.isStreamingResponse(statusCode) {
			w.stopDeadline()
		}
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *deadlineResponseWriter) isStreamingResponse(statusCode int) bool {
	if statusCode == http.StatusSwitchingProtocols {
		return true
	}

	contentType, _, _ := strings.Cut(w.Header().Get("Content-Type"), ";")
	return strings.TrimSpace(contentType) == "text/event-stream"
}

func (w *deadlineResponseWriter) Write(data []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(data)
}

func (w *deadlineResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}

	// A hijacked connection is no longer a request we can put a deadline on.
	w.stopDeadline()
	return hijacker.Hijack()
}

func (w *deadlineResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
