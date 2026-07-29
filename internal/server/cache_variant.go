package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"time"
)

// A resource that negotiates is stored as two kinds of record: a VARIANT INDEX
// at the resource's own key, naming the fields it varies on, and a VARIANT at
// the key those fields' values produce.
//
// A non-varying resource is stored exactly as before -- one record at its own
// key, one lookup, one write. That is the overwhelming majority of responses,
// and it is why the index is a separate record rather than a wrapper around
// every entry.

const (
	// cacheKeyVersion salts every key this build computes, so entries written by
	// a proxy that predates variant indexes live in a disjoint key space.
	//
	// It is not belt and braces. gob silently drops fields the receiving type
	// lacks, so an older binary decodes an index as a response with StatusCode
	// 0 and a nil body, and replaying that calls WriteHeader(0), which panics
	// net/http. Disjoint key spaces make the mixed-version read unreachable
	// rather than merely unlikely. The cost is one lifetime of cold shared cache
	// at one release, on a fleet that just restarted anyway.
	cacheKeyVersion = "2"

	// variantDigestLength is how much of a variant key's hash the index records.
	// It only has to distinguish variants of one resource from each other, and a
	// collision costs a refused store, never a wrong body.
	variantDigestLength = 16
)

// entryIsResponse reports whether a record is a stored response at all.
//
// Every path that hands bytes to a client goes through it, because the
// alternative -- an index, or a record only partly understood -- has no status
// to write. cacheableStatuses contains no zero and the response writer always
// records the status net/http gave it, so a real stored response cannot fail
// this.
func entryIsResponse(entry *CacheEntry) bool {
	return entry != nil && entry.StatusCode >= 100
}

// entryIsIndex reports whether a record names a resource's variants rather than
// being one of them.
func entryIsIndex(entry *CacheEntry) bool {
	return entry != nil && entry.StatusCode == 0 && len(entry.VaryOn) > 0
}

// storageKeyFor is where an entry belongs: the resource's own key when it does
// not negotiate, and the key its Vary fields' values produced when it does.
//
// It is the only function that answers that question, and it answers it for both
// halves of the cache -- the store path calls it to place an entry, the serve
// path calls it to decide whether an entry already in hand belongs to this
// request. A design where those two could disagree is one that eventually hands
// a client somebody else's variant.
func storageKeyFor(entry *CacheEntry, primaryKey string) string {
	if entry.VariantKey == "" {
		return primaryKey
	}

	return entry.VariantKey
}

// variantKeyFor is the key a request's values for varyOn produce. With no fields
// it is the resource's own key, which is what makes a non-varying response cost
// nothing extra.
func variantKeyFor(primaryKey string, varyOn []string, r *http.Request) string {
	if len(varyOn) == 0 {
		return primaryKey
	}

	hasher := sha256.New()
	writeKeyField(hasher, primaryKey)

	for _, field := range varyOn {
		writeKeyField(hasher, field)
		writeKeyField(hasher, keyValueFor(r, field))
	}

	// Kept inside the resource's own namespace, and with no extra colon: Purge
	// scans "kp:c:<service>:*", and cache stats reads the service back by
	// splitting on the LAST colon. A variant key with a segment of its own would
	// be swept correctly but attributed to a service called "<service>:<hash>".
	return primaryKey + hex.EncodeToString(hasher.Sum(nil))[:variantDigestLength]
}

// entryAnswers reports whether a stored entry may answer this request.
//
// This is RFC 9111 section 4.1's secondary-key match, and it is computed from
// THE ENTRY'S OWN vary list -- never from the index that led here, and never
// from the key the entry was read from. That is what makes every wrong guess
// upstream of it cost a miss instead of a wrong body: a stale index, a
// coalescing group keyed before anyone knew the resource negotiates, a lease
// waiter handed the holder's different variant. None of them can pass this.
func entryAnswers(entry *CacheEntry, primaryKey string, r *http.Request) bool {
	if !entryIsResponse(entry) {
		return false
	}

	if variantKeyFor(primaryKey, entry.VaryOn, r) != storageKeyFor(entry, primaryKey) {
		return false
	}

	// A body the target encoded is only an answer for a client that can read it.
	return entryReadableBy(entry, r)
}

// cacheLookup is where one request is looking. It starts at the resource and
// moves to a variant when an index says the resource negotiates.
type cacheLookup struct {
	// primary is the resource's own key, and never changes. Every variant key
	// derives from it, and the inflight group and the lease both key on it.
	primary string
	// variant is the key actually being read or written, which equals primary
	// until an index redirects it.
	variant string
	// index is the variant index this lookup followed, if any. Carrying it
	// avoids re-reading it in order to admit a new variant.
	index *CacheEntry
}

func newCacheLookup(primary string) cacheLookup {
	return cacheLookup{primary: primary, variant: primary}
}

// following redirects the lookup to the variant an index names for this request.
func (l cacheLookup) following(index *CacheEntry, r *http.Request) cacheLookup {
	l.index = index
	l.variant = variantKeyFor(l.primary, index.VaryOn, r)

	return l
}

// newVariantIndex is the record that points a later lookup at the right variant.
// It carries the service and path so a purge can find it: an index a purge
// cannot see is a pointer to bodies that are already gone.
func newVariantIndex(entry *CacheEntry, primaryKey string, variants []string) *CacheEntry {
	return &CacheEntry{
		Service:  entry.Service,
		Path:     entry.Path,
		VaryOn:   slices.Clone(entry.VaryOn),
		Variants: variants,
		StoredAt: entry.StoredAt,
		// Outliving its variants by a margin: an index that expires first costs
		// a cold lookup on every variant it was pointing at, which is far worse
		// than one lingering a little past the last of them. The floor matters
		// for a short-lived resource, whose index would otherwise expire as fast
		// as the bodies it indexes and never be there when it is needed.
		FreshFor:             max(entry.FreshFor+entry.StaleWhileRevalidate, cacheVariantIndexMinTTL),
		StaleWhileRevalidate: 0,
	}
}

// admitVariant decides whether a resource may hold one more representation, and
// returns the index to publish alongside it.
//
// The cap is enforced from the digest set on the index the lookup has ALREADY
// read, so it costs no keyspace walk and no widening of CacheStore. Over the
// cap the variant is simply not stored: the response still reaches the client
// and the request is a plain miss, which is exactly what an uncacheable response
// does today.
//
// First-N-wins, and the set is relearned whenever the resource's shape changes,
// so shifting popularity is followed without churn.
func admitVariant(options CacheOptions, index *CacheEntry, entry *CacheEntry, primaryKey string) (*CacheEntry, bool) {
	if len(entry.VaryOn) == 0 {
		// Not a variant at all; it replaces whatever was at the resource's key,
		// index included.
		return nil, true
	}

	digest := variantDigest(storageKeyFor(entry, primaryKey))

	// An index for a different shape is not this resource's index any more.
	if index == nil || !slices.Equal(index.VaryOn, entry.VaryOn) {
		return newVariantIndex(entry, primaryKey, []string{digest}), true
	}

	if slices.Contains(index.Variants, digest) {
		// Already admitted. Republish so the index outlives the variant it is
		// pointing at.
		return newVariantIndex(entry, primaryKey, index.Variants), true
	}

	if len(index.Variants) >= options.maxVariants() {
		return nil, false
	}

	return newVariantIndex(entry, primaryKey, append(slices.Clone(index.Variants), digest)), true
}

// variantDigest is the short form of a variant key the index records. A
// collision costs a refused store, never a wrong body -- the key itself is what
// selects an entry, and entryAnswers re-derives it in full.
func variantDigest(variantKey string) string {
	hash := sha256.Sum256([]byte(variantKey))

	return hex.EncodeToString(hash[:])[:variantDigestLength]
}

// cacheVariantIndexMinTTL keeps an index from expiring the instant it is
// written for a resource with a very short lifetime.
const cacheVariantIndexMinTTL = time.Minute
