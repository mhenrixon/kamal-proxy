package server

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

// X-Cache tells a client, and anyone reading an access log, which of the three
// paths answered it.
const (
	cacheStatusHit   = "HIT"
	cacheStatusMiss  = "MISS"
	cacheStatusStale = "STALE"
)

// Metric outcomes. They are finer than the header: a coalesced response is a
// hit to the client but a very different thing to whoever is sizing the cache.
//
// Exactly one of hit, miss, stale and coalesced is recorded per request the
// cache considered, so they sum to the request count and a hit rate can be read
// straight off them. The rest describe what the cache did rather than what a
// client got, and are deliberately outside that sum.
const (
	cacheResultHit       = "hit"
	cacheResultMiss      = "miss"
	cacheResultStale     = "stale"
	cacheResultCoalesced = "coalesced"

	cacheResultStore = "store"
	cacheResultError = "error"
	// cacheResultRevalidated is a background stale-while-revalidate fetch. It
	// has no client waiting on it, so counting it as a miss -- which it was
	// until this label existed -- inflated the miss count by the revalidation
	// rate and understated the hit rate on exactly the workload the feature is
	// for.
	cacheResultRevalidated = "revalidated"
	// cacheResultNotModified is a revalidation the target answered 304, which
	// refreshed the entry without transferring its body again.
	cacheResultNotModified = "not_modified"
)

type CacheConfig struct {
	Service string
	Options CacheOptions
	// Store may be nil, which passes every request straight through. Services
	// restored from the state file are built before the store is installed.
	Store CacheStore
	// Variant separates entries that must not answer each other's requests even
	// at the same URL -- a rollout group above all, whose targets are running a
	// different version of the application.
	Variant func(*http.Request) string
}

// CacheMiddleware answers requests from stored responses. It sits below this
// service's authentication, rate limit and redirects, so nothing is ever served
// from the cache that would not have been served from the target, and above the
// load balancer, so a hit costs no target selection at all.
type CacheMiddleware struct {
	config   CacheConfig
	next     http.Handler
	inflight *inflightGroup

	// now is a seam for tests; nothing else replaces it.
	now func() time.Time
}

func WithCacheMiddleware(config CacheConfig, next http.Handler) *CacheMiddleware {
	return &CacheMiddleware{
		config:   config,
		next:     next,
		inflight: newInflightGroup(),
		now:      time.Now,
	}
}

func (h *CacheMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.config.Store == nil || !h.config.Options.Enabled || !requestMayUseCache(r) {
		h.next.ServeHTTP(w, r)
		return
	}

	key := cacheKey(h.config.Service, h.variantFor(r), r, h.config.Options)

	// A request may refuse the stored copy for itself and still populate the
	// cache for everyone behind it, which is what makes a reload useful.
	if requestAllowsStoredResponse(r) {
		if entry, found := h.config.Store.Get(r.Context(), key); found && entryReadableBy(entry, r) {
			now := h.now()

			if entry.needsRevalidation(now) {
				// RFC 5861: answer from the stale copy now, refresh behind it.
				h.revalidate(r, key, entry)
				h.replay(w, r, entry, cacheStatusStale, cacheResultStale, now)
				return
			}

			if entry.servable(now) {
				h.replay(w, r, entry, cacheStatusHit, cacheResultHit, now)
				return
			}
		}
	}

	h.fetch(w, r, key)
}

// Private

func (h *CacheMiddleware) fetch(w http.ResponseWriter, r *http.Request, key string) {
	call, leader := h.inflight.join(key)

	if leader {
		var stored *CacheEntry
		defer func() { h.inflight.settle(key, call, stored) }()

		metrics.Tracker.TrackCacheEvent(h.config.Service, cacheResultMiss)
		stored = h.forward(w, r, key, func() { h.inflight.settle(key, call, nil) })
		return
	}

	select {
	case <-call.done:
		if call.entry != nil {
			h.replay(w, r, call.entry, cacheStatusHit, cacheResultCoalesced, h.now())
			return
		}
	case <-r.Context().Done():
		// The client gave up while queued behind the fetch.
		return
	}

	// The leader's response turned out not to be shareable, so this request has
	// to ask for its own. It does not register as a new leader: whatever made
	// the response unshareable will do so again.
	metrics.Tracker.TrackCacheEvent(h.config.Service, cacheResultMiss)
	h.forward(w, r, key, nil)
}

// forward sends the request upstream, keeping a copy of the response if it may
// be stored. It returns the entry it stored, which is also what any request
// coalesced behind this one is answered from.
func (h *CacheMiddleware) forward(w http.ResponseWriter, r *http.Request, key string, onUnstorable func()) *CacheEntry {
	entry, _ := h.forwardRecording(w, r, key, onUnstorable)
	return entry
}

// forwardRecording is forward plus the status the target answered with, which
// the revalidation path needs in order to recognise a 304.
func (h *CacheMiddleware) forwardRecording(w http.ResponseWriter, r *http.Request, key string, onUnstorable func()) (*CacheEntry, int) {
	recorder := &cachingResponseWriter{
		ResponseWriter: w,
		options:        h.config.Options,
		cacheStatus:    cacheStatusMiss,
		bodyExpected:   r.Method != http.MethodHead,
		onUnstorable:   onUnstorable,
	}

	h.next.ServeHTTP(recorder, r)
	recorder.finish()

	entry := recorder.entry(h.config.Service, r, h.now())
	if entry == nil {
		h.reportRefusal(r, recorder.refusal)
		return nil, recorder.statusCode
	}

	h.store(r, key, entry)
	return entry, recorder.statusCode
}

// store writes an entry, detached from the request: the client may already have
// disconnected, and the response it paid for should still reach the cache.
func (h *CacheMiddleware) store(r *http.Request, key string, entry *CacheEntry) {
	if err := h.config.Store.Set(context.WithoutCancel(r.Context()), key, entry); err != nil {
		slog.Warn("Failed to store cached response", "service", h.config.Service, "path", r.URL.Path, "error", err)
		metrics.Tracker.TrackCacheEvent(h.config.Service, cacheResultError)
		return
	}

	metrics.Tracker.TrackCacheEvent(h.config.Service, cacheResultStore)
}

// reportRefusal records why a response was not stored. Without it, a service
// sitting at 100% miss looks the same whether the target never marks anything
// public, the response varies on a header the key does not carry, or the body is
// simply over the size limit.
func (h *CacheMiddleware) reportRefusal(r *http.Request, refusal cacheRefusal) {
	if refusal == cacheRefusalNone {
		return
	}

	metrics.Tracker.TrackCacheRefusal(h.config.Service, string(refusal))

	attrs := []any{"service", h.config.Service, "path", r.URL.Path, "reason", string(refusal)}
	if advice := refusal.advice(); advice != "" {
		attrs = append(attrs, "advice", advice)
	}
	slog.Debug("Not caching response", attrs...)
}

// revalidate refreshes a stale entry behind the request that was just answered
// from it. Joining the same group as a foreground fetch is what keeps a burst of
// stale hits to a single upstream request.
//
// The refresh carries the stored entry's own validator rather than the client's
// -- a client may be holding something older, or nothing at all, and the
// question being asked is whether *this entry* is still current. A 304 then
// costs no body at all: the stored copy is given a fresh lifetime in place.
func (h *CacheMiddleware) revalidate(r *http.Request, key string, stored *CacheEntry) {
	call, leader := h.inflight.join(key)
	if !leader {
		return
	}

	// Nobody is waiting on this fetch, so it must not inherit the client's
	// cancellation -- nor its logging context, which belongs to the response
	// already on its way out.
	ctx := context.WithValue(context.WithoutCancel(r.Context()), contextKeyRequestContext, &loggingRequestContext{})
	ctx, cancel := context.WithTimeout(ctx, DefaultCacheRevalidateTimeout)

	background := r.Clone(ctx)
	background.Body = http.NoBody
	background.ContentLength = 0
	stripPreconditions(background.Header)
	validated := addStoredValidators(background.Header, stored)

	go func() {
		defer cancel()

		var refreshed *CacheEntry
		defer func() { h.inflight.settle(key, call, refreshed) }()

		metrics.Tracker.TrackCacheEvent(h.config.Service, cacheResultRevalidated)

		entry, statusCode := h.forwardRecording(backgroundResponseWriter{header: http.Header{}}, background, key, nil)

		// A 304 is only meaningful against a validator we actually sent. Without
		// one it says nothing about the stored copy, so it is left to be counted
		// as an ordinary refusal.
		if entry == nil && validated && statusCode == http.StatusNotModified {
			refreshed = stored.refreshed(h.config.Options, h.now())
			h.store(background, key, refreshed)
			metrics.Tracker.TrackCacheEvent(h.config.Service, cacheResultNotModified)
			return
		}

		refreshed = entry
	}()
}

// addStoredValidators makes the refresh conditional on the entry still being
// current, and reports whether it could. An entry the target gave no validator
// for is refreshed by a plain fetch.
func addStoredValidators(header http.Header, stored *CacheEntry) bool {
	validated := false

	if etag := stored.Header.Get("ETag"); etag != "" {
		header.Set("If-None-Match", etag)
		validated = true
	}

	// Only when there is no ETag: sending both invites a target to answer the
	// weaker of the two.
	if lastModified := stored.Header.Get("Last-Modified"); !validated && lastModified != "" {
		header.Set("If-Modified-Since", lastModified)
		validated = true
	}

	return validated
}

// replay writes a stored response to a client.
func (h *CacheMiddleware) replay(w http.ResponseWriter, r *http.Request, entry *CacheEntry, status, result string, now time.Time) {
	header := w.Header()
	for name, values := range entry.Header {
		header[name] = slices.Clone(values)
	}

	header.Set("X-Cache", status)
	header.Set("Age", strconv.FormatInt(int64(entry.age(now).Seconds()), 10))

	if statusAllowsBody(entry.StatusCode) {
		header.Set("Content-Length", strconv.Itoa(len(entry.Body)))
	}

	w.WriteHeader(entry.StatusCode)

	// A HEAD is answered from the stored GET, headers and all, minus the body
	// it is defined not to carry.
	if r.Method != http.MethodHead && len(entry.Body) > 0 {
		if _, err := w.Write(entry.Body); err != nil {
			slog.Debug("Failed to write cached response", "service", h.config.Service, "path", r.URL.Path, "error", err)
		}
	}

	metrics.Tracker.TrackCacheEvent(h.config.Service, result)
}

// preconditionHeaders make a request conditional on the client's own copy. A
// revalidation is not that request: it exists to replace the stored entry, so it
// has to ask for the whole response.
//
// Carrying them meant a client holding an expired copy with an ETag got a
// revalidation that the target answered 304. A 304 is not storable, so nothing
// was written, the inflight call settled with nothing, and the next stale hit
// started another revalidation -- turning the single-flight guarantee into one
// upstream fetch per stale request, on exactly the workload
// stale-while-revalidate exists to protect.
var preconditionHeaders = []string{
	"If-None-Match",
	"If-Modified-Since",
	"If-Match",
	"If-Unmodified-Since",
	"If-Range",
}

func stripPreconditions(header http.Header) {
	for _, name := range preconditionHeaders {
		header.Del(name)
	}
}

func (h *CacheMiddleware) variantFor(r *http.Request) string {
	if h.config.Variant == nil {
		return ""
	}

	return h.config.Variant(r)
}

// backgroundResponseWriter receives a background revalidation's response, which
// exists only to be stored.
type backgroundResponseWriter struct {
	header http.Header
}

func (w backgroundResponseWriter) Header() http.Header            { return w.header }
func (w backgroundResponseWriter) Write(data []byte) (int, error) { return len(data), nil }
func (w backgroundResponseWriter) WriteHeader(statusCode int)     {}
func (w backgroundResponseWriter) Flush()                         {}
