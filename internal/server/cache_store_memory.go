package server

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"time"
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

	stored := entry.clone()
	size := stored.size()

	s.lock.Lock()
	defer s.lock.Unlock()

	if existing, found := s.records[key]; found {
		s.removeElement(existing)
	}

	// An entry that can never fit must not empty the cache trying to make room.
	if size > s.maxBytes {
		return nil
	}

	s.records[key] = s.order.PushFront(&memoryCacheRecord{key: key, entry: stored, size: size})
	s.bytes += size

	for s.bytes > s.maxBytes {
		oldest := s.order.Back()
		if oldest == nil {
			break
		}
		s.removeElement(oldest)
	}

	return nil
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

	return nil
}

// Private

// removeElement must be called with the lock held.
func (s *memoryCacheStore) removeElement(element *list.Element) {
	record := element.Value.(*memoryCacheRecord)

	s.order.Remove(element)
	delete(s.records, record.key)
	s.bytes -= record.size
}
