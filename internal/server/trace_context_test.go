package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTraceContextMode(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expected      TraceContextMode
		expectedError string
	}{
		{name: "empty is the default", value: "", expected: TraceContextPropagate},
		{name: "blank is the default", value: "  ", expected: TraceContextPropagate},
		{name: "off", value: "off", expected: TraceContextOff},
		{name: "propagate", value: "propagate", expected: TraceContextPropagate},
		{name: "generate", value: "generate", expected: TraceContextGenerate},
		{name: "uppercase", value: "GENERATE", expected: TraceContextGenerate},

		{name: "unknown", value: "sample", expectedError: `trace-context: "sample" is not a trace context mode`},
		{name: "boolean", value: "true", expectedError: "trace-context:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := ParseTraceContextMode(tt.value)

			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, mode)
		})
	}
}

func TestParseTraceparent(t *testing.T) {
	const (
		traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
		spanID  = "00f067aa0ba902b7"
	)

	tests := []struct {
		name          string
		values        []string
		valid         bool
		expectedFlags string
	}{
		{name: "the spec's example", values: []string{"00-" + traceID + "-" + spanID + "-01"}, valid: true, expectedFlags: "01"},
		{name: "unsampled", values: []string{"00-" + traceID + "-" + spanID + "-00"}, valid: true, expectedFlags: "00"},

		// A version we do not know may append fields; the spec says to read the
		// ones we understand and ignore the rest rather than restart the trace.
		{name: "future version with extra fields", values: []string{"cc-" + traceID + "-" + spanID + "-09-what-the-future-holds"}, valid: true, expectedFlags: "09"},
		{name: "future version without extra fields", values: []string{"cc-" + traceID + "-" + spanID + "-01"}, valid: true, expectedFlags: "01"},

		{name: "missing", values: nil, valid: false},
		{name: "empty", values: []string{""}, valid: false},
		{name: "two headers", values: []string{"00-" + traceID + "-" + spanID + "-01", "00-" + traceID + "-" + spanID + "-01"}, valid: false},
		{name: "too few fields", values: []string{"00-" + traceID + "-" + spanID}, valid: false},
		{name: "version 00 with extra fields", values: []string{"00-" + traceID + "-" + spanID + "-01-extra"}, valid: false},
		{name: "version ff is forbidden", values: []string{"ff-" + traceID + "-" + spanID + "-01"}, valid: false},
		{name: "version too short", values: []string{"0-" + traceID + "-" + spanID + "-01"}, valid: false},
		{name: "all-zero trace id", values: []string{"00-" + strings.Repeat("0", 32) + "-" + spanID + "-01"}, valid: false},
		{name: "all-zero span id", values: []string{"00-" + traceID + "-" + strings.Repeat("0", 16) + "-01"}, valid: false},
		{name: "short trace id", values: []string{"00-" + traceID[1:] + "-" + spanID + "-01"}, valid: false},
		{name: "long span id", values: []string{"00-" + traceID + "-" + spanID + "0-01"}, valid: false},
		{name: "uppercase hex", values: []string{"00-" + strings.ToUpper(traceID) + "-" + spanID + "-01"}, valid: false},
		{name: "non-hex trace id", values: []string{"00-" + strings.Repeat("g", 32) + "-" + spanID + "-01"}, valid: false},
		{name: "non-hex flags", values: []string{"00-" + traceID + "-" + spanID + "-0z"}, valid: false},
		{name: "surrounding whitespace", values: []string{" 00-" + traceID + "-" + spanID + "-01"}, valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, ok := parseTraceparent(tt.values)

			if !tt.valid {
				assert.False(t, ok)
				return
			}

			require.True(t, ok)
			assert.Equal(t, traceID, tc.TraceID)
			assert.Equal(t, spanID, tc.SpanID)
			assert.Equal(t, tt.expectedFlags, tc.Flags)
		})
	}
}

func TestTraceContext_GeneratedValueRoundTrips(t *testing.T) {
	first := newTraceContext()
	second := newTraceContext()

	assert.NotEqual(t, first.TraceID, second.TraceID)
	assert.NotEqual(t, first.SpanID, second.SpanID)

	parsed, ok := parseTraceparent([]string{first.String()})
	require.True(t, ok, "generated %q does not parse as a traceparent", first.String())
	assert.Equal(t, first, parsed)

	// Sampled, deliberately: an app receiving `00` would suppress the trace it
	// would otherwise have sampled itself.
	assert.Equal(t, "01", first.Flags)
}

// testTraceRequest builds a request already carrying the logging request
// context that LoggingMiddleware installs in production, since that is where
// the trace middleware records what it found.
func testTraceRequest(t *testing.T) (*http.Request, *loggingRequestContext) {
	t.Helper()

	lrc := &loggingRequestContext{}
	r := httptest.NewRequest("GET", "/", nil)

	return r.WithContext(context.WithValue(r.Context(), contextKeyRequestContext, lrc)), lrc
}

func TestTraceContextMiddleware_Off(t *testing.T) {
	const incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	var seen *http.Request
	handler := WithTraceContextMiddleware(TraceContextOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
	}))

	r, lrc := testTraceRequest(t)
	r.Header.Set("Traceparent", incoming)
	handler.ServeHTTP(httptest.NewRecorder(), r)

	require.NotNil(t, seen)
	// Off means unread, not stripped: every other header reaches the target,
	// and this one is no different.
	assert.Equal(t, incoming, seen.Header.Get("Traceparent"))
	assert.Empty(t, lrc.TraceID)
}

func TestTraceContextMiddleware_Propagate(t *testing.T) {
	const incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	tests := []struct {
		name            string
		traceparent     string
		tracestate      string
		expectedHeader  string
		expectedTraceID string
		expectedSpanID  string
	}{
		{
			name:            "valid header is logged and left alone",
			traceparent:     incoming,
			tracestate:      "vendor=value",
			expectedHeader:  incoming,
			expectedTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			expectedSpanID:  "00f067aa0ba902b7",
		},
		{
			// Nothing is invented in propagate mode: a proxy that minted a span
			// id it never reports would leave the app parented to a span no
			// backend has.
			name:           "missing header stays missing",
			expectedHeader: "",
		},
		{
			name:           "malformed header is passed through untouched",
			traceparent:    "not-a-traceparent",
			tracestate:     "vendor=value",
			expectedHeader: "not-a-traceparent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen *http.Request
			handler := WithTraceContextMiddleware(TraceContextPropagate, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r
			}))

			r, lrc := testTraceRequest(t)
			if tt.traceparent != "" {
				r.Header.Set("Traceparent", tt.traceparent)
			}
			if tt.tracestate != "" {
				r.Header.Set("Tracestate", tt.tracestate)
			}

			handler.ServeHTTP(httptest.NewRecorder(), r)

			require.NotNil(t, seen)
			assert.Equal(t, tt.expectedHeader, seen.Header.Get("Traceparent"))
			assert.Equal(t, tt.tracestate, seen.Header.Get("Tracestate"))
			assert.Equal(t, tt.expectedTraceID, lrc.TraceID)
			assert.Equal(t, tt.expectedSpanID, lrc.SpanID)
		})
	}
}

func TestTraceContextMiddleware_Generate(t *testing.T) {
	const incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	tests := []struct {
		name               string
		traceparent        string
		tracestate         string
		expectSameHeader   bool
		expectedTracestate string
	}{
		{
			name:               "a valid trace is joined, not restarted",
			traceparent:        incoming,
			tracestate:         "vendor=value",
			expectSameHeader:   true,
			expectedTracestate: "vendor=value",
		},
		{
			name: "a missing trace is started",
		},
		{
			// The tracestate belongs to the trace we just discarded, so the spec
			// requires dropping it rather than grafting it onto the new one.
			name:        "a malformed trace is restarted and its tracestate dropped",
			traceparent: "00-invalid-00f067aa0ba902b7-01",
			tracestate:  "vendor=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen *http.Request
			handler := WithTraceContextMiddleware(TraceContextGenerate, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r
			}))

			r, lrc := testTraceRequest(t)
			if tt.traceparent != "" {
				r.Header.Set("Traceparent", tt.traceparent)
			}
			if tt.tracestate != "" {
				r.Header.Set("Tracestate", tt.tracestate)
			}

			handler.ServeHTTP(httptest.NewRecorder(), r)

			require.NotNil(t, seen)
			assert.Equal(t, tt.expectedTracestate, seen.Header.Get("Tracestate"))

			forwarded := seen.Header.Get("Traceparent")
			tc, ok := parseTraceparent([]string{forwarded})
			require.True(t, ok, "forwarded %q is not a valid traceparent", forwarded)

			if tt.expectSameHeader {
				assert.Equal(t, tt.traceparent, forwarded)
			} else {
				assert.NotEqual(t, tt.traceparent, forwarded)
			}

			assert.Equal(t, tc.TraceID, lrc.TraceID)
			assert.Equal(t, tc.SpanID, lrc.SpanID)
		})
	}
}

// Multiple traceparent headers are invalid per the spec, and in generate mode
// the replacement has to collapse them to one rather than append a third.
func TestTraceContextMiddleware_GenerateReplacesDuplicateHeaders(t *testing.T) {
	const incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	var seen *http.Request
	handler := WithTraceContextMiddleware(TraceContextGenerate, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
	}))

	r, lrc := testTraceRequest(t)
	r.Header.Add("Traceparent", incoming)
	r.Header.Add("Traceparent", incoming)

	handler.ServeHTTP(httptest.NewRecorder(), r)

	require.NotNil(t, seen)
	require.Len(t, seen.Header.Values("Traceparent"), 1)

	forwarded := seen.Header.Get("Traceparent")
	assert.NotEqual(t, incoming, forwarded)

	tc, ok := parseTraceparent([]string{forwarded})
	require.True(t, ok, "forwarded %q is not a valid traceparent", forwarded)
	assert.Equal(t, tc.TraceID, lrc.TraceID)
	assert.Equal(t, tc.SpanID, lrc.SpanID)
}
