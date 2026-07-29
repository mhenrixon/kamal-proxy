package server

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/basecamp/kamal-proxy/internal/metrics"
)

// fileCacheEntrySuffix marks the files this store owns, so anything else in the
// directory is left alone rather than decoded and discarded.
const fileCacheEntrySuffix = ".entry"

// fileCacheStore keeps entries as files under a directory, so what it holds
// outlives the process. That is the whole reason it exists: with the in-process
// store a proxy restart empties the cache, and the first request for an asset
// that has not changed in a year then wakes a sleeping container to fetch it.
//
// It is a single-host store. It deliberately does not implement CacheLeaser --
// on one proxy the in-process single flight is already the lease, and
// arbitrating with nobody would cost a round trip to learn what is already
// known. See CacheLeaser's own comment, which the memory store follows for the
// same reason.
//
// An index is held in memory for the same reasons the memory store holds one:
// Purge addresses entries by service and path prefix, and the budget needs
// sizes and a recency order. It is rebuilt from disk on open.
type fileCacheStore struct {
	dir      string
	maxBytes int64

	lock     sync.Mutex
	records  map[string]*list.Element
	order    *list.List
	bytes    int64
	services map[string]*cacheServiceUsage

	evictedFresh int64
	evictedStale int64
	oversized    int64
}

// fileCacheEnvelope is what actually lands on disk. The filename is a hash of
// the cache key, which is not reversible, so the key travels with the entry --
// otherwise a reopened store holds files it cannot address. Gob, like
// encodeCacheEntry, so there is one serialisation format rather than two.
type fileCacheEnvelope struct {
	Key   string
	Entry *CacheEntry
}

// fileCacheRecord is the index entry. The body never lives here -- only what is
// needed to find, size, purge and expire the file it points at.
type fileCacheRecord struct {
	key      string
	service  string
	path     string
	size     int64
	expires  time.Time
	fresh    time.Time
	filename string
}

func newFileCacheStore(dir string, maxBytes int64) (*fileCacheStore, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultCacheMemorySize
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to open cache directory %q: %w", dir, err)
	}

	store := &fileCacheStore{
		dir:      dir,
		maxBytes: maxBytes,
		records:  map[string]*list.Element{},
		order:    list.New(),
		services: map[string]*cacheServiceUsage{},
	}

	store.rebuildIndex()

	return store, nil
}

// rebuildIndex reads what a previous process left behind. A file that cannot be
// read or decoded is dropped rather than propagated: one bad file must not make
// the whole cache unopenable, which would turn a corrupt entry into a proxy that
// will not start.
func (s *fileCacheStore) rebuildIndex() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		slog.Warn("Could not read cache directory; starting empty", "dir", s.dir, "error", err)
		return
	}

	now := time.Now()
	restored := 0

	for _, file := range entries {
		if file.IsDir() || !strings.HasSuffix(file.Name(), fileCacheEntrySuffix) {
			continue
		}

		filename := filepath.Join(s.dir, file.Name())

		key, entry, err := s.readEnvelope(filename)
		if err != nil {
			slog.Warn("Dropping unreadable cache file", "file", filename, "error", err)
			_ = os.Remove(filename)
			continue
		}

		// Its stale window has passed, so it can answer nothing. Reclaim now
		// rather than carry it until the budget forces it out.
		if !entry.servable(now) {
			_ = os.Remove(filename)
			continue
		}

		s.index(key, entry, filename, fileSize(file))
		restored++
	}

	if restored > 0 {
		slog.Info("Restored cache from disk", "dir", s.dir, "entries", restored, "bytes", s.bytes)
	}
}

func (s *fileCacheStore) Get(ctx context.Context, key string) (*CacheEntry, bool) {
	s.lock.Lock()
	element, found := s.records[key]
	if !found {
		s.lock.Unlock()
		return nil, false
	}

	record := element.Value.(*fileCacheRecord)

	if time.Now().After(record.expires) {
		s.removeElement(element)
		s.lock.Unlock()
		return nil, false
	}

	s.order.MoveToFront(element)
	filename := record.filename
	s.lock.Unlock()

	// Read outside the lock: a disk read is not something to hold the whole
	// store's mutex through, and the file is immutable once renamed into place.
	entry, err := s.readFile(filename)
	if err != nil {
		// Fail open. A file that vanished or was corrupted underneath us is a
		// miss, never an error to the caller.
		slog.Warn("Cache file unreadable; treating as a miss", "file", filename, "error", err)
		s.forget(key)
		return nil, false
	}

	return entry, true
}

func (s *fileCacheStore) Set(ctx context.Context, key string, entry *CacheEntry) error {
	if entry.ttl() <= 0 {
		return nil
	}

	stored := entry.clone()
	size := stored.size()

	if size > s.maxBytes {
		s.lock.Lock()
		s.oversized++
		s.lock.Unlock()
		return nil
	}

	filename, err := s.writeFile(key, stored)
	if err != nil {
		// Fail open: a write that could not land is a logged error, and the
		// request it came from has already been answered.
		slog.Warn("Could not write cache entry", "key", key, "error", err)
		return nil
	}

	for _, eviction := range s.store(key, stored, filename, size) {
		state := cacheEvictionStale
		if eviction.fresh {
			state = cacheEvictionFresh
		}
		metrics.Tracker.TrackCacheEviction(eviction.service, state)
	}

	return nil
}

// store indexes the written file and returns what had to be dropped to fit it.
func (s *fileCacheStore) store(key string, entry *CacheEntry, filename string, size int64) []cacheEviction {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Replacing an entry. The filename is a hash of the key, so the new write
	// landed on the SAME path -- removing "the old file" here would delete the
	// one just written and turn every subsequent Get into a miss. Drop the index
	// entry only and let the rename that already happened stand.
	if existing, found := s.records[key]; found {
		s.dropIndex(existing)
	}

	s.index(key, entry, filename, size)

	evictions := []cacheEviction{}
	now := time.Now()

	for s.bytes > s.maxBytes {
		oldest := s.order.Back()
		if oldest == nil {
			break
		}

		record := oldest.Value.(*fileCacheRecord)
		evictions = append(evictions, cacheEviction{
			service: record.service,
			fresh:   now.Before(record.fresh),
		})

		if record.fresh.After(now) {
			s.evictedFresh++
		} else {
			s.evictedStale++
		}

		s.removeElement(oldest)
	}

	return evictions
}

// index must be called with the lock held, or during construction.
func (s *fileCacheStore) index(key string, entry *CacheEntry, filename string, size int64) {
	now := time.Now()

	record := &fileCacheRecord{
		key:     key,
		service: entry.Service,
		path:    entry.Path,
		size:    size,
		// Derived rather than stored on the entry: age() nets off the age the
		// response already had when it arrived, which a bare StoredAt+FreshFor
		// would not.
		expires:  now.Add(entry.ttl()),
		fresh:    now.Add(entry.FreshFor - entry.age(now)),
		filename: filename,
	}

	s.records[key] = s.order.PushFront(record)
	s.bytes += size
	s.addUsage(record.service, size)
}

func (s *fileCacheStore) Purge(ctx context.Context, service, pathPrefix string) (int, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	purged := 0
	for element := s.order.Front(); element != nil; {
		next := element.Next()

		record := element.Value.(*fileCacheRecord)
		if record.service == service && strings.HasPrefix(record.path, pathPrefix) {
			s.removeElement(element)
			purged++
		}

		element = next
	}

	return purged, nil
}

// Close drops the index but leaves the files. That is the point: the next
// process reads them back.
func (s *fileCacheStore) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.records = map[string]*list.Element{}
	s.order.Init()
	s.bytes = 0
	s.services = map[string]*cacheServiceUsage{}

	return nil
}

// Private

// pathForKey reports where a key's file lives, whether or not it exists. Used by
// tests to corrupt an entry the way a torn disk would.
func (s *fileCacheStore) pathForKey(key string) (string, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	element, found := s.records[key]
	if !found {
		return "", false
	}

	return element.Value.(*fileCacheRecord).filename, true
}

// filenameForKey hashes the key: a cache key carries a URL, a method and
// negotiated headers, none of which is safe to put in a path.
func (s *fileCacheStore) filenameForKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+fileCacheEntrySuffix)
}

// writeFile writes to a temp file and renames it into place, so a reader never
// sees a partial entry and a crash mid-write leaves no half-file behind.
func (s *fileCacheStore) writeFile(key string, entry *CacheEntry) (string, error) {
	data, err := encodeCacheEnvelope(fileCacheEnvelope{Key: key, Entry: entry})
	if err != nil {
		return "", err
	}

	filename := s.filenameForKey(key)

	temp, err := os.CreateTemp(s.dir, ".writing-*")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()

	if _, err := temp.Write(data); err != nil {
		temp.Close()
		_ = os.Remove(tempName)
		return "", err
	}

	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return "", err
	}

	if err := os.Rename(tempName, filename); err != nil {
		_ = os.Remove(tempName)
		return "", err
	}

	return filename, nil
}

func (s *fileCacheStore) readFile(filename string) (*CacheEntry, error) {
	_, entry, err := s.readEnvelope(filename)
	return entry, err
}

func (s *fileCacheStore) readEnvelope(filename string) (string, *CacheEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", nil, err
	}

	envelope, err := decodeCacheEnvelope(data)
	if err != nil {
		return "", nil, err
	}
	if envelope.Entry == nil {
		return "", nil, fmt.Errorf("cache file %q holds no entry", filename)
	}

	return envelope.Key, envelope.Entry, nil
}

// forget drops an index entry whose file turned out to be unusable.
func (s *fileCacheStore) forget(key string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if element, found := s.records[key]; found {
		s.removeElement(element)
	}
}

// removeElement must be called with the lock held. It removes the file as well
// as the index entry: a purge that left the file behind would be undone by the
// next restart.
func (s *fileCacheStore) removeElement(element *list.Element) {
	record := element.Value.(*fileCacheRecord)
	s.dropIndex(element)

	if err := os.Remove(record.filename); err != nil && !os.IsNotExist(err) {
		slog.Warn("Could not remove cache file", "file", record.filename, "error", err)
	}
}

// dropIndex forgets an entry without touching the file, for the one case where
// the file is still wanted: a replacement that reused the same path.
func (s *fileCacheStore) dropIndex(element *list.Element) {
	record := element.Value.(*fileCacheRecord)

	s.order.Remove(element)
	delete(s.records, record.key)
	s.bytes -= record.size
	s.removeUsage(record.service, record.size)
}

func (s *fileCacheStore) addUsage(service string, size int64) {
	usage, found := s.services[service]
	if !found {
		usage = &cacheServiceUsage{}
		s.services[service] = usage
	}

	usage.bytes += size
	usage.entries++
}

func (s *fileCacheStore) removeUsage(service string, size int64) {
	usage, found := s.services[service]
	if !found {
		return
	}

	usage.bytes -= size
	usage.entries--

	if usage.entries <= 0 {
		delete(s.services, service)
	}
}

func fileSize(file os.DirEntry) int64 {
	info, err := file.Info()
	if err != nil {
		return 0
	}
	return info.Size()
}

func encodeCacheEnvelope(envelope fileCacheEnvelope) ([]byte, error) {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(envelope); err != nil {
		return nil, fmt.Errorf("failed to encode cache envelope: %w", err)
	}

	return buffer.Bytes(), nil
}

func decodeCacheEnvelope(data []byte) (fileCacheEnvelope, error) {
	var envelope fileCacheEnvelope
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("failed to decode cache envelope: %w", err)
	}

	return envelope, nil
}
