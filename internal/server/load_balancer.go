package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	LoadBalancerAffinityOptOutHeader = "X-Writer-Affinity"
	LoadBalancerTargetHeader         = "X-Kamal-Target"
	LoadBalancerWriteCookieName      = "kamal-writer"
)

var ErrorNoHealthyTargets = errors.New("no healthy targets")

type TargetList []*Target

func NewTargetList(targetURLs, readerURLs []string, options TargetOptions) (TargetList, error) {
	targets := TargetList{}

	for _, name := range targetURLs {
		target, err := NewTarget(name, options)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}

	for _, name := range readerURLs {
		target, err := NewReadOnlyTarget(name, options)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}

	return targets, nil
}

func (tl TargetList) Names() []string {
	names := []string{}
	for _, target := range tl {
		names = append(names, target.Address())
	}
	return names
}

func (tl TargetList) HasReaders() bool {
	for _, target := range tl {
		if target.ReadOnly() {
			return true
		}
	}
	return false
}

func (tl TargetList) BeginHealthChecks(stateConsumer TargetStateConsumer) {
	for _, target := range tl {
		target.BeginHealthChecks(stateConsumer)
	}
}

func (tl TargetList) StopHealthChecks() {
	for _, target := range tl {
		target.StopHealthChecks()
	}
}

func (tl TargetList) targetsMatchingReadonly(readonly bool) TargetList {
	result := TargetList{}
	for _, target := range tl {
		if target.ReadOnly() == readonly {
			result = append(result, target)
		}
	}
	return result
}

type LoadBalancer struct {
	all                         TargetList
	writers                     TargetList
	readers                     TargetList
	writerAffinityTimeout       time.Duration
	readTargetsAcceptWebsockets bool
	writerIndex                 int
	readerIndex                 int
	lock                        sync.Mutex

	multiTarget            bool
	hasReaders             bool
	weighted               bool
	persistentHealthChecks bool
	waitForHealthyContext  context.Context
	markHealthy            context.CancelFunc

	// retryPolicy is fork-only; see retry.go.
	retryPolicy RetryPolicy
}

func NewLoadBalancer(targets TargetList, writerAffinityTimeout time.Duration, readTargetsAcceptWebsockets bool) *LoadBalancer {
	waitForHealthyContext, markHealthy := context.WithCancel(context.Background())

	lb := &LoadBalancer{
		all:                         targets,
		writers:                     TargetList{},
		readers:                     TargetList{},
		writerAffinityTimeout:       writerAffinityTimeout,
		readTargetsAcceptWebsockets: readTargetsAcceptWebsockets,

		multiTarget:           len(targets) > 1,
		hasReaders:            targets.HasReaders(),
		weighted:              targets.hasWeights(),
		waitForHealthyContext: waitForHealthyContext,
		markHealthy:           markHealthy,
	}

	lb.all.BeginHealthChecks(lb)

	return lb
}

func (lb *LoadBalancer) Targets() TargetList {
	return lb.all
}

func (lb *LoadBalancer) WriteTargets() TargetList {
	return lb.all.targetsMatchingReadonly(false)
}

func (lb *LoadBalancer) ReadTargets() TargetList {
	return lb.all.targetsMatchingReadonly(true)
}

// HealthyTargets returns the currently healthy targets, writers first.
func (lb *LoadBalancer) HealthyTargets() TargetList {
	lb.lock.Lock()
	defer lb.lock.Unlock()

	targets := TargetList{}
	targets = append(targets, lb.writers...)
	targets = append(targets, lb.readers...)
	return targets
}

func (lb *LoadBalancer) WaitUntilHealthy(timeout time.Duration) error {
	// Locked because ResumeFromSleep replaces this context at runtime. Until
	// scale-to-zero existed it was written once in NewLoadBalancer before the
	// value was published, and reading it unlocked was safe.
	lb.lock.Lock()
	waitForHealthy := lb.waitForHealthyContext
	lb.lock.Unlock()

	ctx, cancel := context.WithTimeout(waitForHealthy, timeout)
	defer cancel()

	<-ctx.Done()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w (%s)", ErrorTargetFailedToBecomeHealthy, timeout)
	}

	return nil
}

func (lb *LoadBalancer) MarkAllHealthy() {
	for _, target := range lb.all {
		target.updateState(TargetStateHealthy)
	}
	lb.updateHealthyTargets()
}

// RecheckHealth restarts health checking on targets that were assumed healthy
// when restored from saved state. Restored targets were never verified, so a
// dead one must be demoted (503) rather than served blindly (502s forever).
// Checks stay active for the lifetime of this load balancer, so a recovered
// target also rejoins the pool.
func (lb *LoadBalancer) RecheckHealth() {
	lb.lock.Lock()
	lb.persistentHealthChecks = true
	lb.lock.Unlock()

	lb.all.BeginHealthChecks(lb)
}

// SuspendForSleep empties the pool and stops probing, so a container that is
// deliberately stopped is neither routed to nor dialled once a second for the
// whole nap.
//
// Called before the containers go down. The idle controller holds arriving
// requests while this runs, so the empty pool is never observable to a client.
func (lb *LoadBalancer) SuspendForSleep() {
	lb.all.StopHealthChecks()

	for _, target := range lb.all {
		target.updateState(TargetStateUnhealthy)
	}

	lb.lock.Lock()
	defer lb.lock.Unlock()

	lb.writers = TargetList{}
	lb.readers = TargetList{}
}

// ResumeFromSleep puts the pool back in the state a fresh deployment starts in --
// unverified, health-checked -- and re-arms WaitUntilHealthy so a caller can wait
// for the woken containers to actually answer.
//
// Re-arming is the whole point. A single-target pool stops probing once its
// target first goes healthy, so markHealthy has already fired and the context is
// already cancelled; without this, WaitUntilHealthy returns nil instantly against
// a container that has not started, and the wake forwards its held request into a
// connection refused.
//
// The context is replaced rather than cancelled: WaitUntilHealthy reports any
// non-deadline cancellation as success, so cancelling would tell a waiter that
// parked before the resume "healthy" at the exact moment every target was marked
// unverified.
func (lb *LoadBalancer) ResumeFromSleep() {
	lb.lock.Lock()
	lb.waitForHealthyContext, lb.markHealthy = context.WithCancel(context.Background())
	lb.lock.Unlock()

	// Adding, not Healthy: a successful probe promotes Adding to Healthy, while a
	// failed one only ever demotes Healthy to Unhealthy. A container that never
	// comes up therefore stays out of the pool instead of flapping into it.
	for _, target := range lb.all {
		target.updateState(TargetStateAdding)
	}

	// Safe to reuse rather than needing a separate restart path: BeginHealthChecks
	// now assigns stateConsumer under the inflight lock. NewHealthCheck runs one
	// immediate probe before it starts ticking, so readiness costs a round trip
	// rather than a whole check interval.
	lb.all.BeginHealthChecks(lb)
}

func (lb *LoadBalancer) Dispose() {
	lb.all.StopHealthChecks()
}

func (lb *LoadBalancer) DrainAll(timeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(len(lb.all))

	for _, target := range lb.all {
		go func() {
			target.Drain(timeout)
			wg.Done()
		}()
	}

	wg.Wait()
}

func (lb *LoadBalancer) StartRequest(w http.ResponseWriter, r *http.Request) func() {
	// Selecting a target is deferred into the closure when retries are enabled,
	// so that waiting for one happens after the service lock is released.
	if lb.retryPolicy.enabled() {
		return func() { lb.serveWithRetries(w, r) }
	}

	target, req, readRequest, err := lb.claimTarget(r)
	if err != nil {
		SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
		return nil
	}

	if lb.writerAffinityTimeout > 0 && lb.hasReaders && !readRequest {
		w = newLoadBalancerReponseWriter(w, lb.writerAffinityTimeout)
	}

	lb.setTargetHeader(req, target)

	return func() {
		target.SendRequest(w, req)
	}
}

// TargetStateConsumer

func (lb *LoadBalancer) TargetStateChanged(target *Target) {
	lb.updateHealthyTargets()
}

// Private

func (lb *LoadBalancer) claimTarget(req *http.Request) (*Target, *http.Request, bool, error) {
	lb.lock.Lock()
	defer lb.lock.Unlock()

	readRequest := lb.isReadRequest(req)
	treatAsReadRequest := readRequest && !lb.hasWriteCookie(req)

	target := lb.nextTarget(treatAsReadRequest)
	if target == nil {
		return nil, nil, false, ErrorNoHealthyTargets
	}

	req, err := target.StartRequest(req)
	return target, req, readRequest, err
}

// nextTarget rotates through the healthy targets of the pool the request
// belongs to. Weighted pools are fork-only and rotate by share instead; see
// target_weight.go. Nothing weighted means the plain rotation, so a deployment
// that sets no weights behaves exactly as it did before they existed.
func (lb *LoadBalancer) nextTarget(reader bool) *Target {
	if reader && len(lb.readers) > 0 {
		if lb.weighted {
			return lb.readers.nextWeighted()
		}

		lb.readerIndex = (lb.readerIndex + 1) % len(lb.readers)
		return lb.readers[lb.readerIndex]
	}

	if len(lb.writers) > 0 {
		if lb.weighted {
			return lb.writers.nextWeighted()
		}

		lb.writerIndex = (lb.writerIndex + 1) % len(lb.writers)
		return lb.writers[lb.writerIndex]
	}

	return nil
}

func (lb *LoadBalancer) isReadRequest(req *http.Request) bool {
	return (req.Method == http.MethodGet || req.Method == http.MethodHead) &&
		(lb.readTargetsAcceptWebsockets || !isWebSocketRequest(req))
}

func isWebSocketRequest(req *http.Request) bool {
	return req.Method == http.MethodGet &&
		strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

func (lb *LoadBalancer) updateHealthyTargets() {
	lb.lock.Lock()
	defer lb.lock.Unlock()

	lb.writers = TargetList{}
	lb.readers = TargetList{}

	healthyCount := 0
	for _, target := range lb.all {
		if target.State() == TargetStateHealthy {
			healthyCount++

			if target.ReadOnly() {
				lb.readers = append(lb.readers, target)
			} else {
				lb.writers = append(lb.writers, target)
			}
		}
	}

	// If we have a single target, we can stop health-checking once it's
	// healthy. Even if it becomes unhealthy later, taking it out of the pool
	// won't help. Restored targets are the exception: their health was assumed
	// rather than observed, so their checks are kept running.
	if !lb.multiTarget && len(lb.writers) == 1 && !lb.persistentHealthChecks {
		lb.all.StopHealthChecks()
	}

	// Notify we've become healthy only if *all* targets are healthy.
	if healthyCount == len(lb.all) {
		lb.markHealthy()
	}
}

func (lb *LoadBalancer) setTargetHeader(req *http.Request, target *Target) {
	address := target.Address()

	if target.options.ForwardHeaders {
		prior := req.Header[LoadBalancerTargetHeader]
		if len(prior) > 0 {
			address = strings.Join(prior, ", ") + ", " + address
		}
	}

	req.Header.Set(LoadBalancerTargetHeader, address)
}

func (lb *LoadBalancer) hasWriteCookie(r *http.Request) bool {
	cookie, err := r.Cookie(LoadBalancerWriteCookieName)
	if err != nil {
		return false
	}

	expires, err := strconv.ParseInt(cookie.Value, 10, 64)
	if err != nil {
		return false
	}

	return time.Now().UnixMilli() < expires
}

type loadBalancerResponseWriter struct {
	http.ResponseWriter
	headerWritten         bool
	writerAffinityTimeout time.Duration
}

func newLoadBalancerReponseWriter(w http.ResponseWriter, writerAffinityTimeout time.Duration) *loadBalancerResponseWriter {
	return &loadBalancerResponseWriter{
		ResponseWriter:        w,
		headerWritten:         false,
		writerAffinityTimeout: writerAffinityTimeout,
	}
}

func (w *loadBalancerResponseWriter) WriteHeader(statusCode int) {
	w.setWriterAffinityCookie()

	w.ResponseWriter.WriteHeader(statusCode)
	w.headerWritten = true
}

func (w *loadBalancerResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(b)
}

func (w *loadBalancerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ResponseWriter does not implement http.Hijacker")
	}

	return hijacker.Hijack()
}

func (w *loadBalancerResponseWriter) Flush() {
	flusher, ok := w.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}

func (w *loadBalancerResponseWriter) setWriterAffinityCookie() {
	if w.Header().Get(LoadBalancerAffinityOptOutHeader) != "false" {
		expires := time.Now().Add(w.writerAffinityTimeout)

		cookie := &http.Cookie{
			Name:     LoadBalancerWriteCookieName,
			Value:    strconv.FormatInt(expires.UnixMilli(), 10),
			Path:     "/",
			HttpOnly: true,
			Expires:  expires.Add(time.Second),
		}

		http.SetCookie(w, cookie)
	}

	w.Header().Del(LoadBalancerAffinityOptOutHeader)
}
