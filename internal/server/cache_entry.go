package server

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/http"
	"time"
)

// cacheEntryOverhead is a flat allowance for the bookkeeping around a stored
// response -- map buckets, slice headers, the key itself. It keeps a cache of
// many tiny entries from overrunning its byte budget several times over.
const cacheEntryOverhead = 256

// CacheEntry is one stored response. It travels between proxy instances through
// a shared store, so every field it needs must be on it: nothing may be
// recovered from the local process.
type CacheEntry struct {
	// Service and Path are carried for purging, which addresses entries by the
	// service that stored them and optionally by a path prefix.
	Service string
	Path    string

	StatusCode int
	Header     http.Header
	Body       []byte

	// StoredAt is when this proxy wrote the entry; InitialAge is how old the
	// response already was when it arrived, per its own Age header.
	StoredAt   time.Time
	InitialAge time.Duration

	// FreshFor is the shared lifetime the response asked for, and
	// StaleWhileRevalidate the RFC 5861 window after it during which the entry
	// may still answer requests while a fresh copy is fetched behind them.
	FreshFor             time.Duration
	StaleWhileRevalidate time.Duration
}

// age is how old the response is now, counting the age it arrived with. A clock
// that moved backwards reads as zero rather than as a negative age, which would
// make an expired entry look new.
func (e *CacheEntry) age(now time.Time) time.Duration {
	elapsed := now.Sub(e.StoredAt)
	if elapsed < 0 {
		elapsed = 0
	}

	return e.InitialAge + elapsed
}

func (e *CacheEntry) fresh(now time.Time) bool {
	return e.age(now) < e.FreshFor
}

// servable reports whether the entry may still answer a request, either because
// it is fresh or because it is inside its stale-while-revalidate window.
func (e *CacheEntry) servable(now time.Time) bool {
	return e.age(now) < e.FreshFor+e.StaleWhileRevalidate
}

// needsRevalidation reports whether serving this entry should also kick off a
// background fetch, which is true exactly in the stale window.
func (e *CacheEntry) needsRevalidation(now time.Time) bool {
	return !e.fresh(now) && e.servable(now)
}

// ttl is how much longer the entry can be of any use, which is what a store with
// its own expiry should be told. It nets off the age the response arrived with.
func (e *CacheEntry) ttl() time.Duration {
	ttl := e.FreshFor + e.StaleWhileRevalidate - e.InitialAge
	if ttl < 0 {
		return 0
	}

	return ttl
}

func (e *CacheEntry) size() int64 {
	size := int64(len(e.Body) + len(e.Service) + len(e.Path) + cacheEntryOverhead)

	for name, values := range e.Header {
		size += int64(len(name))
		for _, value := range values {
			size += int64(len(value))
		}
	}

	return size
}

// clone returns a copy safe to hand to a request goroutine. The memory store
// keeps entries live, and a served response must not be able to mutate the
// stored headers on its way out.
func (e *CacheEntry) clone() *CacheEntry {
	copied := *e
	copied.Header = e.Header.Clone()

	return &copied
}

// encodeCacheEntry serializes an entry for a shared store. gob rather than JSON:
// a response body is arbitrary bytes, and JSON would base64 it into a third more
// space than it needs on every store and every fetch.
func encodeCacheEntry(entry *CacheEntry) ([]byte, error) {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(entry); err != nil {
		return nil, fmt.Errorf("failed to encode cache entry: %w", err)
	}

	return buffer.Bytes(), nil
}

func decodeCacheEntry(data []byte) (*CacheEntry, error) {
	var entry CacheEntry
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entry); err != nil {
		return nil, fmt.Errorf("failed to decode cache entry: %w", err)
	}

	return &entry, nil
}
