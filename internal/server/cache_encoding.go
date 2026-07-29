package server

import (
	"net/http"
	"slices"
	"strings"
)

// Accept-Encoding is the one request header that cannot be keyed on as sent.
// The same client capability arrives written a dozen ways -- "gzip, deflate,
// br" and "br;q=0.9, gzip;q=1.0, deflate;q=0.8" mean exactly the same thing --
// so keying on the raw string splits one resource across an entry per browser
// version. Keying on what the client will actually accept collapses them back
// into a handful of buckets.
//
// This only applies when an operator names accept-encoding in
// --cache-vary-header. Left out, as it is by default, the cache stores what the
// target produced and the compression middleware encodes it per client, so one
// entry serves everyone.

// keyableEncodings are the content codings this proxy will key on. Anything else
// a client offers is dropped rather than keyed: exotic codings no target here
// emits would otherwise fragment the cache for nothing.
var keyableEncodings = []string{EncodingBrotli, "deflate", EncodingGzip, encodingIdentity, EncodingZstd}

const encodingIdentity = "identity"

// normalizeAcceptEncoding reduces a client's Accept-Encoding to the sorted set of
// codings it will actually accept, which is what decides whether two requests may
// share a stored response.
//
// Identity is included unless refused outright, per RFC 9110: a client that says
// nothing about it still accepts an unencoded body.
func normalizeAcceptEncoding(header string) string {
	accepted, wildcard, hasWildcard := parseAcceptEncoding(header)

	usable := make([]string, 0, len(keyableEncodings))
	for _, encoding := range keyableEncodings {
		quality, named := accepted[encoding]
		switch {
		case named:
			// An explicit q=0 is a refusal, and it really does change which
			// entries this client may be served.
			if quality > 0 {
				usable = append(usable, encoding)
			}
		case encoding == encodingIdentity:
			// Acceptable unless the client said otherwise, whatever the
			// wildcard says.
			usable = append(usable, encoding)
		case hasWildcard && wildcard > 0:
			usable = append(usable, encoding)
		}
	}

	return strings.Join(usable, ",")
}

// clientAcceptsEncoding reports whether this client can read a body in the given
// coding.
//
// It guards the serve path rather than the key: an entry may have been written
// before the key carried an encoding dimension, or left behind when
// --cache-vary-header stopped naming accept-encoding. Handing a client bytes it
// cannot decode is the one outcome that must never happen, so the check is made
// again at the point of serving rather than trusted to the key alone.
func clientAcceptsEncoding(r *http.Request, contentEncoding string) bool {
	contentEncoding = strings.ToLower(strings.TrimSpace(contentEncoding))
	if contentEncoding == "" || contentEncoding == encodingIdentity {
		return true
	}

	accepted, wildcard, hasWildcard := parseAcceptEncoding(joinHeaderValues(r, "Accept-Encoding"))

	if quality, named := accepted[contentEncoding]; named {
		return quality > 0
	}

	return hasWildcard && wildcard > 0
}

// entryReadableBy reports whether a stored entry can be served to this request.
func entryReadableBy(entry *CacheEntry, r *http.Request) bool {
	return clientAcceptsEncoding(r, entry.Header.Get("Content-Encoding"))
}

// keyValueFor returns what the cache key should carry for a request header. Every
// header is keyed on as sent, except Accept-Encoding -- see above.
func keyValueFor(r *http.Request, name string) string {
	value := joinHeaderValues(r, name)
	if name == acceptEncodingHeader {
		return normalizeAcceptEncoding(value)
	}

	return value
}

// joinHeaderValues reads every field line a header was sent on, not just the
// first.
//
// RFC 9110 section 5.3 lets a client send a list header as several field lines,
// and says they mean exactly what the single comma-separated line means. Reading
// only the first was a cache-poisoning hole rather than a missed optimization: a
// request sending "Accept: text/html" then "Accept: application/json" keyed
// identically to one sending only the first, so two clients wanting different
// representations shared one entry and whichever arrived first decided what the
// other got.
func joinHeaderValues(r *http.Request, name string) string {
	values := r.Header.Values(name)

	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	default:
		return strings.Join(values, ", ")
	}
}

// encodingIsKeyable reports whether a coding is one the cache would key on, which
// is what decides whether a target-encoded response can be stored at all.
func encodingIsKeyable(contentEncoding string) bool {
	return slices.Contains(keyableEncodings, strings.ToLower(strings.TrimSpace(contentEncoding)))
}
