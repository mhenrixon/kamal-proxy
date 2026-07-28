package server

import (
	"bufio"
	"net"
	"net/http"
	"slices"
)

// ErrorInterceptMiddleware replaces error responses the target produced itself
// with the proxy's error pages, so a degraded app shows the operator's branded
// page instead of whatever it managed to render. Errors the proxy generates
// (an unreachable target, a timeout) already route through
// ErrorPageMiddleware, so only statuses the target wrote need intercepting.
//
// Only the statuses the service opted into are intercepted; every other
// response streams through untouched.
type ErrorInterceptMiddleware struct {
	statuses []int
	next     http.Handler
}

func WithErrorInterceptMiddleware(statuses []int, next http.Handler) http.Handler {
	return &ErrorInterceptMiddleware{
		statuses: statuses,
		next:     next,
	}
}

func (h *ErrorInterceptMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writer := &interceptingResponseWriter{ResponseWriter: w, statuses: h.statuses}

	h.next.ServeHTTP(writer, r)

	if writer.interceptedStatus != 0 {
		SetErrorResponse(w, r, writer.interceptedStatus, nil)
	}
}

// Private

type interceptingResponseWriter struct {
	http.ResponseWriter
	statuses          []int
	headerWritten     bool
	interceptedStatus int
}

func (w *interceptingResponseWriter) WriteHeader(statusCode int) {
	if w.headerWritten {
		return
	}
	w.headerWritten = true

	if !slices.Contains(w.statuses, statusCode) {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}

	// Nothing reaches the client until ErrorPageMiddleware renders the page, so
	// drop the headers that describe the body we're about to discard. Left in
	// place, they would truncate the error page or have the client decode it as
	// the target's encoding.
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")

	w.interceptedStatus = statusCode
}

func (w *interceptingResponseWriter) Write(data []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	if w.interceptedStatus != 0 {
		// Report the write as successful. Returning an error here would make
		// ReverseProxy panic, and the target has no say in the response anyway.
		return len(data), nil
	}

	return w.ResponseWriter.Write(data)
}

func (w *interceptingResponseWriter) Flush() {
	if w.interceptedStatus != 0 {
		return
	}

	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *interceptingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}

	// A hijacked connection is no longer ours to write an error page to.
	w.headerWritten = true

	return hijacker.Hijack()
}
