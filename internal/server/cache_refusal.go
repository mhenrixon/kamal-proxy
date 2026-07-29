package server

// A cacheRefusal names why a response was not stored. Without one, an operator
// watching a service sit at 100% MISS cannot tell a target that never marks
// anything `public` from a `Vary` the key does not carry from a body over the
// size limit -- three very different problems with three different fixes, and
// no way to tell them apart from outside.
//
// Every value is a bounded, low-cardinality label safe to put on a metric.
type cacheRefusal string

const (
	// cacheRefusalNone means the response may be stored.
	cacheRefusalNone cacheRefusal = ""

	// The service is not deployed with --cache. Recorded for completeness; the
	// middleware short-circuits before reaching the decision in that case.
	cacheRefusalDisabled cacheRefusal = "disabled"

	// cacheRefusalStatus covers every status outside the storable set, 206 and
	// 5xx above all.
	cacheRefusalStatus cacheRefusal = "status"

	// The Cache-Control directives the target sent.
	cacheRefusalNotPublic  cacheRefusal = "not_public"
	cacheRefusalNoStore    cacheRefusal = "no_store"
	cacheRefusalPrivate    cacheRefusal = "private"
	cacheRefusalNoCache    cacheRefusal = "no_cache"
	cacheRefusalNoLifetime cacheRefusal = "no_lifetime"

	// Properties of the response body or its headers.
	cacheRefusalSetCookie       cacheRefusal = "set_cookie"
	cacheRefusalContentRange    cacheRefusal = "content_range"
	cacheRefusalContentEncoding cacheRefusal = "content_encoding"
	cacheRefusalEventStream     cacheRefusal = "event_stream"
	cacheRefusalVary            cacheRefusal = "vary"

	// Decided by the proxy rather than the response: a HEAD has no body to
	// store, a body past --cache-max-body is too big to keep, and a hijacked
	// connection has stopped being a response at all.
	cacheRefusalHeadRequest cacheRefusal = "head_request"
	cacheRefusalTooLarge    cacheRefusal = "too_large"
	cacheRefusalHijacked    cacheRefusal = "hijacked"
)

// advice is the operator-facing hint that goes with a refusal, naming the lever
// that would change it. Empty when there is nothing to be done from the proxy
// side and the target has to change.
func (r cacheRefusal) advice() string {
	switch r {
	case cacheRefusalNotPublic, cacheRefusalNoLifetime:
		return "the target must send Cache-Control: public with an s-maxage or max-age"
	case cacheRefusalSetCookie:
		return "pass --cache-allow-set-cookie if this response is safe to share"
	case cacheRefusalVary:
		return "name the varying header in --cache-vary-header, or the cookie in --cache-vary-cookie"
	case cacheRefusalContentEncoding:
		return "the target encoded this itself; pass --cache-vary-header accept-encoding, or let --compress do the encoding"
	case cacheRefusalTooLarge:
		return "raise --cache-max-body if this response is worth keeping"
	default:
		return ""
	}
}
