package server

import (
	"net/http"
	"slices"
	"strings"
)

// Which dimensions a response actually negotiates on, reduced to the set this
// cache can key.
//
// Before this, a response whose Vary named anything the operator had not listed
// in --cache-vary-header was refused outright. That made a Rails app emitting
// `Vary: Accept` from respond_to, or `Vary: Origin` from rack-cors, cache
// nothing at all -- and the workaround put the named header in the key for every
// path in the service, so fixing one endpoint fragmented the whole cache.

const (
	// maxVaryFields is how many dimensions one response may negotiate on before
	// a shared cache gives up. A response naming more is describing something
	// closer to a per-client body than a cacheable representation.
	maxVaryFields = 8

	varyWildcard = "*"
)

// unkeyableVaryFields differ for practically every client, so keying on them
// would store one copy per client -- a cache that costs memory and returns
// nothing. Cookie is the important one: a `public` response varying on the whole
// Cookie header is almost certainly an application bug, and caching it
// *correctly keyed* would still hold one body per session.
//
// Naming one in --cache-vary-header is the override, and it is deliberately
// awkward: it moves the field into the primary key for the whole service.
var unkeyableVaryFields = []string{
	"authorization",
	"cookie",
	"referer",
	"user-agent",
}

// varyFieldsFor reduces a response's Vary header to the fields the cache should
// key a variant on, or reports why it will not store the response. The second
// return names the offending field for the debug log; it never reaches a metric
// label, where an application-chosen string would be a cardinality bomb inside a
// fix for a cardinality bomb.
func varyFieldsFor(options CacheOptions, header http.Header) ([]string, cacheRefusal, string) {
	declared := varyFieldNames(header)
	encoded := header.Get("Content-Encoding") != ""

	// With automatic variants switched off, the old rule stands exactly: every
	// declared field must already be in the primary key, or nothing is stored.
	if !options.automaticVary() {
		for _, field := range declared {
			if field == varyWildcard {
				return nil, cacheRefusalVary, varyWildcard
			}
			if field == acceptEncodingHeader && !encoded {
				continue
			}
			if !options.coversVaryField(field) {
				return nil, cacheRefusalVary, field
			}
		}

		if encoded && !options.coversVaryField(acceptEncodingHeader) {
			return nil, cacheRefusalContentEncoding, header.Get("Content-Encoding")
		}

		return nil, cacheRefusalNone, ""
	}

	fields := make([]string, 0, len(declared))

	for _, field := range declared {
		// Nothing can be keyed on "vary on everything".
		if field == varyWildcard {
			return nil, cacheRefusalVary, varyWildcard
		}

		// Already in the primary key, so keying it again would cost a second
		// lookup for a dimension the first one already carried.
		if options.coversVaryField(field) {
			continue
		}

		// Accept-Encoding is the one dimension whose treatment depends on the
		// body rather than on Vary. An unencoded response is stored once and
		// encoded per client by the compression middleware above this one, so
		// the near-universal `Vary: Accept-Encoding` costs nothing.
		if field == acceptEncodingHeader && !encoded {
			continue
		}

		if slices.Contains(unkeyableVaryFields, field) {
			return nil, cacheRefusalVaryUnkeyable, field
		}

		fields = append(fields, field)
	}

	// A body the target encoded itself is one particular representation, so the
	// key has to record which -- whether or not the target thought to say so.
	if encoded && !slices.Contains(fields, acceptEncodingHeader) && !options.coversVaryField(acceptEncodingHeader) {
		if !encodingIsKeyable(header.Get("Content-Encoding")) {
			return nil, cacheRefusalContentEncoding, header.Get("Content-Encoding")
		}
		fields = append(fields, acceptEncodingHeader)
	}

	if len(fields) > maxVaryFields {
		return nil, cacheRefusalVaryTooMany, strings.Join(fields, ",")
	}

	slices.Sort(fields)

	if len(fields) == 0 {
		return nil, cacheRefusalNone, ""
	}

	return fields, cacheRefusalNone, ""
}

// varyFieldNames reads every Vary field line, lowercased and deduplicated. A
// header sent as several lines means what the one comma-separated line means.
func varyFieldNames(header http.Header) []string {
	var names []string

	for _, value := range header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			field = strings.ToLower(strings.TrimSpace(field))
			if field == "" || slices.Contains(names, field) {
				continue
			}
			names = append(names, field)
		}
	}

	return names
}
