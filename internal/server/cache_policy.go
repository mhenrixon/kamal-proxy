package server

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The rules deciding what may be cached, keyed on what, and for how long. They
// follow RFC 9111 (HTTP caching, obsoleting RFC 7234) and RFC 5861
// (stale-while-revalidate), and are deliberately stricter than either in two
// places: storing requires an explicit `public` directive rather than a
// heuristic, and a request carrying credentials never touches the cache.

// cacheKeyPrefix namespaces every key this proxy writes, so a Redis instance
// shared with an application's own data cannot collide with it.
const cacheKeyPrefix = "kp:c:"

// cacheableStatuses is RFC 9111 section 15.1's list of statuses a cache may
// store, minus 206: a partial response describes a byte range this proxy never
// tracks, and storing one would answer a later full request with a fragment.
var cacheableStatuses = []int{
	http.StatusOK,
	http.StatusNonAuthoritativeInfo,
	http.StatusNoContent,
	http.StatusMultipleChoices,
	http.StatusMovedPermanently,
	http.StatusPermanentRedirect,
	http.StatusNotFound,
	http.StatusMethodNotAllowed,
	http.StatusGone,
	http.StatusRequestURITooLong,
	http.StatusNotImplemented,
}

type cacheDirectives struct {
	noStore              bool
	noCache              bool
	private              bool
	public               bool
	maxAge               time.Duration
	hasMaxAge            bool
	sMaxAge              time.Duration
	hasSMaxAge           bool
	staleWhileRevalidate time.Duration
	// mustRevalidate covers both must-revalidate and proxy-revalidate. They say
	// the same thing to a shared cache, which is the only kind this is.
	mustRevalidate bool
}

// sharedLifetime is how long a shared cache may treat the response as fresh.
// s-maxage exists precisely to say something different to shared caches than to
// the browser, so it wins outright when present.
func (cd cacheDirectives) sharedLifetime() (time.Duration, bool) {
	if cd.hasSMaxAge {
		return cd.sMaxAge, true
	}
	if cd.hasMaxAge {
		return cd.maxAge, true
	}
	return 0, false
}

func parseCacheControl(values []string) cacheDirectives {
	var directives cacheDirectives

	for _, value := range values {
		for _, token := range splitCacheControl(value) {
			name, argument, hasArgument := strings.Cut(token, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			argument = strings.Trim(strings.TrimSpace(argument), `"`)

			switch name {
			case "no-store":
				directives.noStore = true
			case "no-cache":
				directives.noCache = true
			case "private":
				directives.private = true
			case "public":
				directives.public = true
			case "must-revalidate", "proxy-revalidate":
				directives.mustRevalidate = true
			case "max-age":
				if seconds, ok := parseDeltaSeconds(argument, hasArgument); ok {
					directives.maxAge, directives.hasMaxAge = seconds, true
				}
			case "s-maxage":
				if seconds, ok := parseDeltaSeconds(argument, hasArgument); ok {
					directives.sMaxAge, directives.hasSMaxAge = seconds, true
				}
			case "stale-while-revalidate":
				if seconds, ok := parseDeltaSeconds(argument, hasArgument); ok {
					directives.staleWhileRevalidate = seconds
				}
			}
		}
	}

	return directives
}

// requestMayUseCache reports whether the request can participate in the cache at
// all, either by being answered from it or by populating it.
func requestMayUseCache(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	// A shared cache holding one client's authorized response and handing it to
	// the next is the one failure this feature must never have. RFC 9111 allows
	// it when the response says `public`; we do not, because the response's
	// author and the proxy's operator are often not the same person.
	if r.Header.Get("Authorization") != "" {
		return false
	}

	// Neither a byte range nor a protocol upgrade describes a whole response
	// this cache could store or replay.
	if r.Header.Get("Range") != "" || r.Header.Get("Upgrade") != "" {
		return false
	}

	return !parseCacheControl(r.Header.Values("Cache-Control")).noStore
}

// requestAllowsStoredResponse reports whether a stored response may answer this
// request. A request that refuses one may still populate the cache, which is
// what makes a shift-reload warm the entry for everybody else.
func requestAllowsStoredResponse(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Pragma")), "no-cache") {
		return false
	}

	directives := parseCacheControl(r.Header.Values("Cache-Control"))
	if directives.noCache {
		return false
	}

	return !directives.hasMaxAge || directives.maxAge > 0
}

// responseIsStorable reports whether the response may be stored, and for how
// long it counts as fresh and then as stale-but-servable.
func responseIsStorable(options CacheOptions, statusCode int, header http.Header) (time.Duration, time.Duration, bool) {
	if !options.Enabled || !slices.Contains(cacheableStatuses, statusCode) {
		return 0, 0, false
	}

	directives := parseCacheControl(header.Values("Cache-Control"))

	// Freshness alone is not consent. Requiring `public` means a target that
	// forgets to mark a page private is still never shared between clients.
	if !directives.public || directives.noStore || directives.private {
		return 0, 0, false
	}

	// no-cache permits storing but requires the entry to be validated before
	// every reuse (RFC 9111 section 5.2.2.4). This proxy has no way to validate
	// on the way out, so the only honest answer is not to store it at all --
	// keeping it would mean serving it unvalidated, which is what the directive
	// forbids.
	if directives.noCache {
		return 0, 0, false
	}

	freshFor, ok := directives.sharedLifetime()
	if !ok || freshFor <= 0 {
		return 0, 0, false
	}
	if options.MaxTTL > 0 && freshFor > options.MaxTTL {
		freshFor = options.MaxTTL
	}

	if header.Get("Set-Cookie") != "" && !options.AllowSetCookie {
		return 0, 0, false
	}

	if header.Get("Content-Range") != "" {
		return 0, 0, false
	}

	// A body the target encoded itself is one particular representation, and by
	// default the key does not record which -- handing it to a client that asked
	// for a different encoding, or none, would be bytes it cannot read. Naming
	// accept-encoding in --cache-vary-header puts it in the key and makes these
	// storable, at the cost of an entry per distinct Accept-Encoding string.
	if header.Get("Content-Encoding") != "" && !options.keysOnAcceptEncoding() {
		return 0, 0, false
	}

	// Holding an event stream back to store it is exactly what the client asked
	// us not to do, and its body never ends.
	if normalizeContentType(header.Get("Content-Type")) == eventStreamContentType {
		return 0, 0, false
	}

	if !varyCovered(header, options) {
		return 0, 0, false
	}

	// must-revalidate forbids answering from an entry that has passed its
	// lifetime (RFC 9111 section 5.2.2.2), which is precisely what a
	// stale-while-revalidate window is for. The entry is still worth keeping;
	// it just stops being servable the moment it goes stale.
	staleWhileRevalidate := directives.staleWhileRevalidate
	if directives.mustRevalidate {
		staleWhileRevalidate = 0
	}

	return freshFor, staleWhileRevalidate, true
}

// varyCovered reports whether every dimension the response varies on is one the
// cache accounts for. When it is not, the response is passed through uncached:
// serving a variant keyed without the dimension that produced it would hand one
// client another's content. `--cache-vary-header` is the lever that brings such
// a response back into the cache.
func varyCovered(header http.Header, options CacheOptions) bool {
	for _, value := range header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			field = strings.ToLower(strings.TrimSpace(field))
			if field == "" {
				continue
			}

			if field == "*" {
				return false
			}

			// Accept-Encoding is accounted for without being in the key: the
			// entry holds what the target produced and the compression
			// middleware above encodes it per client. Applications announce
			// this dimension constantly, so treating it as unkeyed would leave
			// almost nothing cacheable.
			if field == acceptEncodingHeader {
				continue
			}

			if !slices.Contains(options.VaryHeaders, field) {
				return false
			}
		}
	}

	return true
}

// cacheKey identifies a stored response. Every proxy in a fleet computes it the
// same way from the request alone, which is what lets them share one store.
func cacheKey(service, variant string, r *http.Request, options CacheOptions) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	hasher := sha256.New()
	// The method is deliberately absent: a HEAD is answered from the stored GET
	// with its body dropped, so both must land on the same key.
	writeKeyField(hasher, service)
	writeKeyField(hasher, variant)
	writeKeyField(hasher, scheme)
	writeKeyField(hasher, r.Host)
	writeKeyField(hasher, r.URL.Path)
	writeKeyField(hasher, r.URL.RawQuery)

	for _, name := range options.VaryHeaders {
		writeKeyField(hasher, name)
		writeKeyField(hasher, r.Header.Get(name))
	}

	for _, name := range options.VaryCookies {
		writeKeyField(hasher, name)
		if cookie, err := r.Cookie(name); err == nil {
			writeKeyField(hasher, cookie.Value)
		} else {
			writeKeyField(hasher, "")
		}
	}

	return cacheKeyPrefix + service + ":" + hex.EncodeToString(hasher.Sum(nil))
}

// Private

// writeKeyField length-prefixes each part, so that a path of "/a" with a query
// of "b" cannot hash the same as a path of "/ab" with no query.
func writeKeyField(hasher hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	hasher.Write(length[:])
	hasher.Write([]byte(value))
}

// splitCacheControl splits on commas that are not inside a quoted string, so a
// directive such as no-cache="Set-Cookie, X-Token" stays one token.
func splitCacheControl(value string) []string {
	var tokens []string
	quoted := false
	start := 0

	for i, char := range value {
		switch {
		case char == '"':
			quoted = !quoted
		case char == ',' && !quoted:
			tokens = append(tokens, value[start:i])
			start = i + 1
		}
	}

	return append(tokens, value[start:])
}

// parseDeltaSeconds reads a delta-seconds argument. A malformed one is reported
// as absent rather than as zero: reading `max-age=abc` as `max-age=0` would
// quietly make the response uncacheable instead of leaving the typo visible.
func parseDeltaSeconds(argument string, hasArgument bool) (time.Duration, bool) {
	if !hasArgument {
		return 0, false
	}

	seconds, err := strconv.ParseInt(argument, 10, 64)
	if err != nil || seconds < 0 {
		return 0, false
	}

	return time.Duration(seconds) * time.Second, true
}
