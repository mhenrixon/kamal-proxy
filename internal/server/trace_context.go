package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

const (
	traceparentHeader = "Traceparent"
	tracestateHeader  = "Tracestate"

	traceIDLength    = 32
	spanIDLength     = 16
	traceFlagsLength = 2
	traceVersionSize = 2
)

// DefaultTraceContextMode leaves the header untouched on the wire but records
// the trace an incoming request already carries, so a deployment that traces
// gets correlated access logs without configuring anything, and one that does
// not is unaffected.
const DefaultTraceContextMode = "propagate"

// TraceContextMode decides what the proxy does with the W3C `traceparent`
// header (https://www.w3.org/TR/trace-context/).
type TraceContextMode string

const (
	// TraceContextOff skips the middleware entirely. The header still reaches
	// the target - every header does - it is simply neither read nor logged.
	TraceContextOff TraceContextMode = "off"

	// TraceContextPropagate logs the trace a valid incoming header names and
	// forwards that header byte for byte.
	TraceContextPropagate TraceContextMode = "propagate"

	// TraceContextGenerate additionally starts a trace when the request carries
	// none, so every request downstream has an id the access log also names.
	TraceContextGenerate TraceContextMode = "generate"
)

// ParseTraceContextMode maps a --trace-context value onto a mode. An empty
// value means the default, so an unset or blank TRACE_CONTEXT boots instead of
// failing.
func ParseTraceContextMode(value string) (TraceContextMode, error) {
	switch mode := TraceContextMode(strings.ToLower(strings.TrimSpace(value))); mode {
	case "":
		return DefaultTraceContextMode, nil
	case TraceContextOff, TraceContextPropagate, TraceContextGenerate:
		return mode, nil
	default:
		return "", fmt.Errorf("trace-context: %q is not a trace context mode; use off, propagate or generate", value)
	}
}

// traceContext is the part of a `traceparent` header the proxy understands.
type traceContext struct {
	TraceID string
	SpanID  string
	Flags   string
}

func (tc traceContext) String() string {
	return "00-" + tc.TraceID + "-" + tc.SpanID + "-" + tc.Flags
}

type TraceContextMiddleware struct {
	mode TraceContextMode
	next http.Handler
}

// WithTraceContextMiddleware installs trace handling, or nothing at all when
// the mode is off - an unused middleware would still cost a header lookup on
// every request.
func WithTraceContextMiddleware(mode TraceContextMode, next http.Handler) http.Handler {
	if mode == TraceContextOff {
		return next
	}

	return &TraceContextMiddleware{
		mode: mode,
		next: next,
	}
}

func (h *TraceContextMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tc, ok := parseTraceparent(r.Header.Values(traceparentHeader))

	if !ok && h.mode == TraceContextGenerate {
		tc = newTraceContext()

		// Set, not Add: the header is invalid precisely when there is more than
		// one of it, and appending would leave it invalid.
		r.Header.Set(traceparentHeader, tc.String())

		// The tracestate describes the trace we just discarded, so the spec
		// requires dropping it rather than grafting it onto the new one.
		r.Header.Del(tracestateHeader)

		ok = true
	}

	if ok {
		lrc := LoggingRequestContext(r)
		lrc.TraceID = tc.TraceID
		lrc.SpanID = tc.SpanID
		lrc.TraceFlags = tc.Flags
	}

	h.next.ServeHTTP(w, r)
}

// parseTraceparent reads a `traceparent` header, returning false for anything
// the spec calls invalid - including more than one of the header, which is how
// a request that crossed two tracing systems arrives.
//
// The span id it returns is the *caller's*, not one the proxy minted. Inventing
// one would make the app a child of a span no backend has ever seen, because
// kamal-proxy exports no spans of its own.
func parseTraceparent(values []string) (traceContext, bool) {
	if len(values) != 1 {
		return traceContext{}, false
	}

	fields := strings.Split(values[0], "-")
	if len(fields) < 4 {
		return traceContext{}, false
	}

	version, traceID, spanID, flags := fields[0], fields[1], fields[2], fields[3]

	// ff is reserved as "invalid version" by the spec; anything else may exist
	// one day, and a version we do not know is allowed to append fields we are
	// told to ignore rather than reject.
	if !isLowerHex(version, traceVersionSize) || version == "ff" {
		return traceContext{}, false
	}
	if version == "00" && len(fields) != 4 {
		return traceContext{}, false
	}

	if !isLowerHex(traceID, traceIDLength) || isAllZeroes(traceID) {
		return traceContext{}, false
	}
	if !isLowerHex(spanID, spanIDLength) || isAllZeroes(spanID) {
		return traceContext{}, false
	}
	if !isLowerHex(flags, traceFlagsLength) {
		return traceContext{}, false
	}

	return traceContext{TraceID: traceID, SpanID: spanID, Flags: flags}, true
}

// newTraceContext starts a trace, marked sampled. The alternative - starting it
// unsampled - is worse than not starting one at all: an app that would have
// made its own sampling decision honors the parent's instead, so `00` here
// silently switches its tracing off.
//
// The flags stay `01` and not `03` even though the trace id below is fully
// random. Trace Context Level 2 defines 0x02 as "this trace id is random", but
// it is still a Candidate Recommendation, and the Level 1 Recommendation this
// file emits version `00` against says of every bit but the sampled one:
// "Vendors MUST set those to zero."
func newTraceContext() traceContext {
	var buffer [(traceIDLength + spanIDLength) / 2]byte

	// crypto/rand.Read cannot fail as of Go 1.24 - it panics rather than
	// returning an error - so there is no failure branch to write.
	_, _ = rand.Read(buffer[:])

	return traceContext{
		TraceID: hex.EncodeToString(buffer[:traceIDLength/2]),
		SpanID:  hex.EncodeToString(buffer[traceIDLength/2:]),
		Flags:   "01",
	}
}

// isLowerHex reports whether value is exactly length lowercase hex digits. The
// spec's fields are lowercase, and an uppercase one is invalid rather than
// merely untidy - accepting it would let two spellings of the same id through.
func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}

	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

func isAllZeroes(value string) bool {
	return strings.Count(value, "0") == len(value)
}
