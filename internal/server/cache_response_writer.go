package server

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"time"
)

// hopByHopHeaders describe the connection a response arrived on rather than the
// response itself, so they must not travel with a stored entry to another client
// -- or, with a shared store, to another proxy entirely.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// cachingResponseWriter passes a response through to the client and, when the
// response says it may be shared, keeps a copy on the way past. Bytes are never
// held back: capturing costs the client no latency, which is what lets the same
// writer sit in front of a streaming response and a storable one alike.
type cachingResponseWriter struct {
	http.ResponseWriter
	options      CacheOptions
	cacheStatus  string
	bodyExpected bool
	// onUnstorable fires as soon as it is known that no entry will come out of
	// this response, so anything waiting for one can stop waiting.
	onUnstorable func()

	statusCode  int
	wroteHeader bool
	released    bool
	hijacked    bool

	capturing            bool
	body                 []byte
	header               http.Header
	initialAge           time.Duration
	freshFor             time.Duration
	staleWhileRevalidate time.Duration
}

func (w *cachingResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}

	w.wroteHeader = true
	w.statusCode = statusCode
	w.Header().Set("X-Cache", w.cacheStatus)
	w.decide()

	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *cachingResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if w.capturing {
		if int64(len(w.body)+len(data)) > w.options.maxBodySize() {
			// Too big to keep, but the client asked for all of it.
			w.abandon()
		} else {
			w.body = append(w.body, data...)
		}
	}

	return w.ResponseWriter.Write(data)
}

func (w *cachingResponseWriter) Flush() {
	if !w.hijacked {
		if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

func (w *cachingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}

	// The connection stops being a response we could frame, let alone store.
	w.hijacked = true
	w.abandon()

	return hijacker.Hijack()
}

// finish settles the outcome once the handler has returned.
func (w *cachingResponseWriter) finish() {
	if w.hijacked {
		return
	}

	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
}

// entry is the stored form of what just went past, or nil if it may not be
// stored.
func (w *cachingResponseWriter) entry(service string, r *http.Request, now time.Time) *CacheEntry {
	if !w.capturing {
		return nil
	}

	return &CacheEntry{
		Service:              service,
		Path:                 r.URL.Path,
		StatusCode:           w.statusCode,
		Header:               w.header,
		Body:                 w.body,
		StoredAt:             now,
		InitialAge:           w.initialAge,
		FreshFor:             w.freshFor,
		StaleWhileRevalidate: w.staleWhileRevalidate,
	}
}

// Private

func (w *cachingResponseWriter) decide() {
	freshFor, stale, storable := responseIsStorable(w.options, w.statusCode, w.Header())

	// A HEAD response is a body-less description of a GET. Storing it would
	// answer later GETs with nothing at all.
	if !storable || !w.bodyExpected {
		w.release()
		return
	}

	w.capturing = true
	w.freshFor = freshFor
	w.staleWhileRevalidate = stale
	w.initialAge = parseAgeHeader(w.Header().Get("Age"))
	w.header = storableHeader(w.Header())
}

func (w *cachingResponseWriter) abandon() {
	w.capturing = false
	w.body = nil
	w.header = nil
	w.release()
}

func (w *cachingResponseWriter) release() {
	if w.released {
		return
	}

	w.released = true
	if w.onUnstorable != nil {
		w.onUnstorable()
	}
}

// storableHeader is the response's headers as another client should see them:
// without the connection framing, and without the fields the cache recomputes
// on every replay.
func storableHeader(header http.Header) http.Header {
	stored := header.Clone()

	for _, name := range hopByHopHeaders {
		stored.Del(name)
	}

	// Recomputed when the entry is served: the age moves, the length follows
	// the stored body, and the status labels the request being answered.
	stored.Del("Age")
	stored.Del("Content-Length")
	stored.Del("X-Cache")

	return stored
}

// parseAgeHeader reads how old the response already was when it reached us. A
// missing or malformed value reads as brand new, which is what a response
// without an Age header is claiming.
func parseAgeHeader(value string) time.Duration {
	if value == "" {
		return 0
	}

	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 {
		return 0
	}

	return time.Duration(seconds) * time.Second
}
