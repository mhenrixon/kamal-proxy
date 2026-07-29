package server

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

// memoryCacheStore keeps entries in this process, capped by total size and
// evicted least-recently-used first. It is the store a single proxy uses when
// no shared one is configured: repeat requests to one node still collapse, but
// nothing is shared with the node beside it.
type memoryCacheStore struct {
	lock     sync.Mutex
	maxBytes int64
	bytes    int64
	records  map[string]*list.Element
	order    *list.List

	// What the store has dropped, which is what --cache-memory-size is tuned
	// against. Fresh and stale are counted apart because only the fresh count
	// says the budget is too small; a full cache shedding stale entries is a
	// cache doing its job.
	evictedFresh int64
	evictedStale int64
	oversized    int64

	// services indexes entries by the service that stored them, so a breakdown
	// costs a map read rather than a walk of the whole list.
	services map[string]*cacheServiceUsage
}

type cacheServiceUsage struct {
	entries int64
	bytes   int64
}

// cacheEviction is one dropped entry, reported to metrics after the lock is
// released -- a Prometheus call under the LRU mutex would put the metrics
// registry on the request path.
type cacheEviction struct {
	service string
	fresh   bool
}

// memoryCacheRecord is what the LRU list holds. It carries its own key so an
// eviction from the back of the list can find the map entry to delete, and its
// own size so the running total does not depend on re-measuring a mutated entry.
type memoryCacheRecord struct {
	key   string
	entry *CacheEntry
	size  int64
}

func newMemoryCacheStore(maxBytes int64) *memoryCacheStore {
	return &memoryCacheStore{
		maxBytes: maxBytes,
		records:  map[string]*list.Element{},
		order:    list.New(),
		services: map[string]*cacheServiceUsage{},
	}
}

func (s *memoryCacheStore) Get(ctx context.Context, key string) (*CacheEntry, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	element, found := s.records[key]
	if !found {
		return nil, false
	}

	record := element.Value.(*memoryCacheRecord)

	// Past its stale window the entry can answer nothing, so drop it here
	// rather than wait for the budget to force it out.
	if !record.entry.servable(time.Now()) {
		s.removeElement(element)
		return nil, false
	}

	s.order.MoveToFront(element)

	// Detached, so a response on its way out cannot mutate what is stored.
	return record.entry.clone(), true
}

func (s *memoryCacheStore) Set(ctx context.Context, key string, entry *CacheEntry) error {
	if entry.ttl() <= 0 {
		return nil
	}

	// Reported after the lock is released: a metrics call is not something to
	// hold the whole store's mutex through.
	for _, eviction := range s.store(key, entry) {
		state := cacheEvictionStale
		if eviction.fresh {
			state = cacheEvictionFresh
		}
		metrics.Tracker.TrackCacheEviction(eviction.service, state)
	}

	return nil
}

// store writes the entry and returns what had to be dropped to fit it.
func (s *memoryCacheStore) store(key string, entry *CacheEntry) []cacheEviction {
	stored := entry.clone()
	size := stored.size()

	s.lock.Lock()
	defer s.lock.Unlock()

	// Replacing an entry with a newer copy of itself is not budget pressure, so
	// it is not counted as an eviction.
	if existing, found := s.records[key]; found {
		s.removeElement(existing)
	}

	// An entry that can never fit must not empty the cache trying to make room.
	// That is a misconfiguration rather than pressure, and reads as its own
	// number.
	if size > s.maxBytes {
		s.oversized++
		return nil
	}

	s.records[key] = s.order.PushFront(&memoryCacheRecord{key: key, entry: stored, size: size})
	s.bytes += size
	s.addUsage(stored.Service, size)

	// Only this loop counts: everywhere else removeElement is called, the entry
	// was already useless or explicitly asked for.
	now := time.Now()
	var evicted []cacheEviction

	for s.bytes > s.maxBytes {
		oldest := s.order.Back()
		if oldest == nil {
			break
		}

		record := oldest.Value.(*memoryCacheRecord)
		evicted = append(evicted, cacheEviction{
			service: record.entry.Service,
			fresh:   record.entry.fresh(now),
		})

		if record.entry.fresh(now) {
			s.evictedFresh++
		} else {
			s.evictedStale++
		}

		s.removeElement(oldest)
	}

	return evicted
}

func (s *memoryCacheStore) Purge(ctx context.Context, service, pathPrefix string) (int, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	purged := 0
	for element := s.order.Front(); element != nil; {
		next := element.Next()

		record := element.Value.(*memoryCacheRecord)
		if record.entry.Service == service && strings.HasPrefix(record.entry.Path, pathPrefix) {
			s.removeElement(element)
			purged++
		}

		element = next
	}

	return purged, nil
}

func (s *memoryCacheStore) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.records = map[string]*list.Element{}
	s.order.Init()
	s.bytes = 0
	s.services = map[string]*cacheServiceUsage{}

	return nil
}

// Private

// removeElement must be called with the lock held.
func (s *memoryCacheStore) removeElement(element *list.Element) {
	record := element.Value.(*memoryCacheRecord)

	s.order.Remove(element)
	delete(s.records, record.key)
	s.bytes -= record.size
	s.removeUsage(record.entry.Service, record.size)
}

// addUsage and removeUsage must be called with the lock held. A service drops
// out of the map entirely when its last entry goes, so a breakdown never shows a
// zero row for a service that is no longer cached.
func (s *memoryCacheStore) addUsage(service string, size int64) {
	usage, found := s.services[service]
	if !found {
		usage = &cacheServiceUsage{}
		s.services[service] = usage
	}

	usage.entries++
	usage.bytes += size
}

func (s *memoryCacheStore) removeUsage(service string, size int64) {
	usage, found := s.services[service]
	if !found {
		return
	}

	usage.entries--
	usage.bytes -= size

	if usage.entries <= 0 {
		delete(s.services, service)
	}
}
