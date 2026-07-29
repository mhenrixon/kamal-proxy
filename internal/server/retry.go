package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// DefaultTargetTryInterval is how long the load balancer pauses between attempts
// when nothing is ready to take the request.
const DefaultTargetTryInterval = time.Millisecond * 250

var contextKeyProxyAttempt = contextKey("proxy-attempt")

// RetryPolicy bounds how long the load balancer keeps trying to place a request
// on a healthy target. A zero TryDuration means one attempt, which is how the
// proxy behaves when retries are not configured.
type RetryPolicy struct {
	TryDuration time.Duration
	TryInterval time.Duration
}

func (p RetryPolicy) enabled() bool {
	return p.TryDuration > 0
}

func (p RetryPolicy) interval() time.Duration {
	if p.TryInterval > 0 {
		return p.TryInterval
	}
	return DefaultTargetTryInterval
}

// RetryPolicy returns the load balancer retry settings carried by these service
// options.
func (so ServiceOptions) RetryPolicy() RetryPolicy {
	return RetryPolicy{
		TryDuration: so.TargetTryDuration,
		TryInterval: so.TargetTryInterval,
	}
}

func (so ServiceOptions) validateRetries() error {
	if so.TargetTryDuration < 0 {
		return fmt.Errorf("%w: target-try-duration cannot be negative", ErrServiceOptionsInvalid)
	}

	if so.TargetTryInterval < 0 {
		return fmt.Errorf("%w: target-try-interval cannot be negative", ErrServiceOptionsInvalid)
	}

	if so.TargetTryInterval > 0 && so.TargetTryDuration == 0 {
		return fmt.Errorf("%w: target-try-interval requires target-try-duration", ErrServiceOptionsInvalid)
	}

	return nil
}

// WithRetryPolicy attaches a retry policy to the load balancer. It is separate
// from NewLoadBalancer so that upstream's constructor signature stays untouched
// across syncs.
func (lb *LoadBalancer) WithRetryPolicy(policy RetryPolicy) *LoadBalancer {
	lb.retryPolicy = policy
	return lb
}

// proxyAttempt collects the failure of a single attempt so that the load
// balancer can decide whether to try another target instead of letting the
// target render an error the client would then be stuck with.
type proxyAttempt struct {
	err error
}

func proxyAttemptFromRequest(r *http.Request) *proxyAttempt {
	attempt, _ := r.Context().Value(contextKeyProxyAttempt).(*proxyAttempt)
	return attempt
}

// serveWithRetries places the request on a target, trying further targets until
// it succeeds or the try duration runs out.
//
// A failure to *select* a target means nothing was forwarded, so any request can
// wait for one to appear. A failure while *proxying* is only retried for
// replayable requests, since the target may already have seen the first attempt.
func (lb *LoadBalancer) serveWithRetries(w http.ResponseWriter, r *http.Request) {
	loop := &retryLoop{lb: lb, deadline: time.Now().Add(lb.retryPolicy.TryDuration)}
	replayable := isReplayableRequest(r)

	if lb.writerAffinityTimeout > 0 && lb.hasReaders && !lb.isReadRequest(r) {
		w = newLoadBalancerReponseWriter(w, lb.writerAffinityTimeout)
	}

	retrying := false

	for {
		var attempt *proxyAttempt
		claiming := r
		// A session pin is honoured on the first attempt only: once its target
		// has failed to serve, the request has to rotate like any other.
		if retrying {
			claiming = ignoreSessionPin(claiming)
		}
		if replayable {
			attempt = &proxyAttempt{}
			claiming = claiming.WithContext(context.WithValue(claiming.Context(), contextKeyProxyAttempt, attempt))
		}

		target, req, _, err := lb.claimTarget(claiming)
		if err != nil {
			if !loop.again(r.Context()) {
				clearSessionPin(w)
				SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
				return
			}
			retrying = true
			continue
		}

		lb.setTargetHeader(req, target)
		w = lb.pinSession(w, r, target)
		target.SendRequest(w, req)

		if attempt == nil || attempt.err == nil {
			return
		}

		if !loop.again(r.Context()) {
			clearSessionPin(w)
			// The original request carries no attempt, so the target renders the
			// response it would have sent had we never deferred it.
			target.handleProxyError(w, r, attempt.err)
			return
		}
		retrying = true
	}
}

// retryLoop paces the attempts. It pauses between them so that a pool with
// nothing healthy in it doesn't spin, but lets a request hop straight to another
// healthy target when one is standing by.
type retryLoop struct {
	lb       *LoadBalancer
	deadline time.Time
	hops     int
}

func (l *retryLoop) again(ctx context.Context) bool {
	if !time.Now().Before(l.deadline) {
		return false
	}

	if l.hops < len(l.lb.HealthyTargets())-1 {
		l.hops++
		return true
	}
	l.hops = 0

	return waitBeforeRetry(ctx, l.deadline, l.lb.retryPolicy.interval())
}

func waitBeforeRetry(ctx context.Context, deadline time.Time, interval time.Duration) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	if interval > remaining {
		interval = remaining
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// isReplayableRequest reports whether a request may be sent to a second target.
// It must be idempotent, and it must have no body: a server request body is
// consumed by the first attempt and cannot be rewound, so replaying one would
// forward an empty body.
func isReplayableRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodTrace, http.MethodPut, http.MethodDelete:
	default:
		return false
	}

	return r.ContentLength == 0
}

// isRetryableProxyError reports whether a proxying failure happened before the
// target could act on the request. Timeouts are deliberately excluded: the
// target accepted the request and may have applied it already.
func (t *Target) isRetryableProxyError(err error, r *http.Request) bool {
	if t.isDraining(err) {
		return true
	}

	if t.isRequestEntityTooLarge(err) || t.isGatewayTimeout(err) ||
		t.isRequestDeadlineExceeded(r) || t.isClientCancellation(err) ||
		isChunkedEncodingError(err) {
		return false
	}

	var opError *net.OpError
	return errors.As(err, &opError)
}
