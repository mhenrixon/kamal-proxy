package server

import "sync"

// inflightGroup collapses concurrent work on one cache key. The first request to
// arrive fetches; the rest wait on it and are answered from what it produced. A
// hot URL that expires therefore costs the application one request rather than
// one per client that happened to ask during the gap.
//
// It also serves the stale-while-revalidate path, where the "leader" is a
// background fetch and nobody waits on it at all -- joining is what stops twenty
// stale hits from starting twenty revalidations.
type inflightGroup struct {
	lock  sync.Mutex
	calls map[string]*inflightCall
}

type inflightCall struct {
	// done is closed once the outcome is known. entry is written before the
	// close and read only after it, so the close orders the handoff.
	done  chan struct{}
	entry *CacheEntry
	once  sync.Once
}

func newInflightGroup() *inflightGroup {
	return &inflightGroup{calls: map[string]*inflightCall{}}
}

// join returns the call in flight for key, and whether this caller is the one
// responsible for completing it.
func (g *inflightGroup) join(key string) (*inflightCall, bool) {
	g.lock.Lock()
	defer g.lock.Unlock()

	if call, found := g.calls[key]; found {
		return call, false
	}

	call := &inflightCall{done: make(chan struct{})}
	g.calls[key] = call

	return call, true
}

// settle releases everyone waiting on the call with the entry to answer from, or
// nil when there is nothing shareable and they must fetch for themselves. It is
// idempotent: the leader settles early with nil the moment it learns the
// response cannot be stored, so followers are not held behind a streaming
// response they can never be given a copy of.
func (g *inflightGroup) settle(key string, call *inflightCall, entry *CacheEntry) {
	call.once.Do(func() {
		call.entry = entry

		g.lock.Lock()
		// Only if this call is still the current one: a later request may
		// already have started its own after an early settle.
		if g.calls[key] == call {
			delete(g.calls, key)
		}
		g.lock.Unlock()

		close(call.done)
	})
}
