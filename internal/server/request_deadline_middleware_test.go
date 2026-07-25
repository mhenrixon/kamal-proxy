package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDeadline      = 50 * time.Millisecond
	testDeadlineSlack = 500 * time.Millisecond
)

// serveWithDeadlineMiddleware runs a request through the deadline middleware and
// reports the cancellation cause observed by the wrapped handler, waiting up to
// testDeadlineSlack for a cancellation that may never arrive.
func serveWithDeadlineMiddleware(t *testing.T, timeout time.Duration, pathTimeouts []PathTimeout, req *http.Request, prepareResponse func(w http.ResponseWriter)) error {
	t.Helper()

	var cause error

	handler := WithRequestDeadlineMiddleware(timeout, NormalizePathTimeouts(pathTimeouts), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if prepareResponse != nil {
			prepareResponse(w)
		}

		select {
		case <-r.Context().Done():
			cause = context.Cause(r.Context())
		case <-time.After(testDeadlineSlack):
		}
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	return cause
}

func TestRequestDeadlineMiddleware_CancelsWithDeadlineCause(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/reports", nil)

	started := time.Now()
	cause := serveWithDeadlineMiddleware(t, testDeadline, nil, req, nil)

	require.ErrorIs(t, cause, ErrorRequestDeadlineExceeded)
	assert.Less(t, time.Since(started), testDeadlineSlack)
}

func TestRequestDeadlineMiddleware_DisabledAndExemptRequests(t *testing.T) {
	websocketRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/cable", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		return req
	}

	sseRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/events", nil)
		req.Header.Set("Accept", "text/event-stream")
		return req
	}

	tests := []struct {
		name         string
		timeout      time.Duration
		pathTimeouts []PathTimeout
		req          *http.Request
	}{
		{
			name:    "no timeout configured",
			timeout: 0,
			req:     httptest.NewRequest(http.MethodGet, "/reports", nil),
		},
		{
			name:         "path override of zero",
			timeout:      testDeadline,
			pathTimeouts: []PathTimeout{{PathPrefix: "/downloads", Timeout: 0}},
			req:          httptest.NewRequest(http.MethodGet, "/downloads/big.zip", nil),
		},
		{
			name:         "path override longer than the request",
			timeout:      testDeadline,
			pathTimeouts: []PathTimeout{{PathPrefix: "/reports", Timeout: time.Hour}},
			req:          httptest.NewRequest(http.MethodGet, "/reports/monthly", nil),
		},
		{
			name:    "websocket upgrade request",
			timeout: testDeadline,
			req:     websocketRequest(),
		},
		{
			name:    "request accepting an event stream",
			timeout: testDeadline,
			req:     sseRequest(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := serveWithDeadlineMiddleware(t, tt.timeout, tt.pathTimeouts, tt.req, nil)

			require.NoError(t, cause)
		})
	}
}

func TestRequestDeadlineMiddleware_StreamingResponsesStopTheDeadline(t *testing.T) {
	tests := []struct {
		name            string
		prepareResponse func(w http.ResponseWriter)
		expectCancelled bool
	}{
		{
			name: "event stream response",
			prepareResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
			},
			expectCancelled: false,
		},
		{
			name: "event stream response with charset",
			prepareResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
				w.WriteHeader(http.StatusOK)
			},
			expectCancelled: false,
		},
		{
			name: "switching protocols response",
			prepareResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			expectCancelled: false,
		},
		{
			name: "ordinary response still carries the deadline",
			prepareResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
			},
			expectCancelled: true,
		},
		{
			name: "chunked response still carries the deadline",
			prepareResponse: func(w http.ResponseWriter) {
				w.Header().Set("Transfer-Encoding", "chunked")
				w.WriteHeader(http.StatusOK)
			},
			expectCancelled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/stream", nil)

			cause := serveWithDeadlineMiddleware(t, testDeadline, nil, req, tt.prepareResponse)

			if tt.expectCancelled {
				require.ErrorIs(t, cause, ErrorRequestDeadlineExceeded)
			} else {
				require.NoError(t, cause)
			}
		})
	}
}

func TestRequestDeadlineMiddleware_PassesResponsesThrough(t *testing.T) {
	handler := WithRequestDeadlineMiddleware(time.Minute, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("ok"))
		w.(http.Flusher).Flush()
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Result().StatusCode)
	assert.Equal(t, "text/plain", w.Result().Header.Get("Content-Type"))
	assert.Equal(t, "ok", w.Body.String())
}
