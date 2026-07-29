package server

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
)

// DefaultSessionAffinityCookieName is the cookie a pinned client carries when
// the deployment does not name one of its own.
const DefaultSessionAffinityCookieName = "kamal-session"

var contextKeyIgnoreSessionPin = contextKey("ignore-session-pin")

// SessionAffinityPolicy asks the load balancer to keep each client on the
// target that first served it, for apps whose session state lives in the
// instance rather than in a shared store. Disabled (the default) leaves target
// selection exactly as it is without it.
type SessionAffinityPolicy struct {
	Enabled    bool
	CookieName string
}

// SessionAffinityPolicy returns the pinning settings carried by these service
// options.
func (so ServiceOptions) SessionAffinityPolicy() SessionAffinityPolicy {
	return SessionAffinityPolicy{
		Enabled:    so.SessionAffinity,
		CookieName: so.SessionAffinityCookieName,
	}
}

func (so ServiceOptions) validateSessionAffinity() error {
	if !so.SessionAffinity {
		if so.SessionAffinityCookieName != "" {
			return fmt.Errorf("%w: session-affinity-cookie requires session-affinity", ErrServiceOptionsInvalid)
		}
		return nil
	}

	if so.SessionAffinityCookieName == "" {
		return nil
	}

	// A cookie carrying an invalid name is silently dropped by net/http when the
	// response is written, which would look like affinity simply not working.
	probe := &http.Cookie{Name: so.SessionAffinityCookieName, Value: "pin"}
	if probe.Valid() != nil {
		return fmt.Errorf("%w: session-affinity-cookie %q is not a valid cookie name", ErrServiceOptionsInvalid, so.SessionAffinityCookieName)
	}

	return nil
}

// WithSessionAffinity attaches a pinning policy to the load balancer. Like
// WithRetryPolicy it is separate from NewLoadBalancer, so that upstream's
// constructor signature stays untouched across syncs.
func (lb *LoadBalancer) WithSessionAffinity(policy SessionAffinityPolicy) *LoadBalancer {
	if policy.Enabled {
		lb.sessionAffinity = newSessionPinner(policy.CookieName, lb.all)
	}

	return lb
}

// sessionPinner maps between a target and the opaque identifier a pinned client
// carries for it.
//
// The identifier is a keyed digest of the target's address rather than the
// address itself, so a cookie tells its holder nothing about the topology
// behind the proxy. The key is fresh per load balancer, which also means a
// guessed address cannot be confirmed by recomputing the digest, and that pins
// from a previous deployment -- whose targets are gone anyway -- are simply
// unrecognized.
type sessionPinner struct {
	cookieName string
	ids        map[*Target]string
}

func newSessionPinner(cookieName string, targets TargetList) *sessionPinner {
	if cookieName == "" {
		cookieName = DefaultSessionAffinityCookieName
	}

	// crypto/rand.Read cannot fail: it panics rather than hand back a short read,
	// which is what makes an unchecked key safe to use here.
	key := make([]byte, sha256.Size)
	rand.Read(key)

	pinner := &sessionPinner{cookieName: cookieName, ids: make(map[*Target]string, len(targets))}
	for _, target := range targets {
		digest := hmac.New(sha256.New, key)
		digest.Write([]byte(target.Address()))
		pinner.ids[target] = hex.EncodeToString(digest.Sum(nil)[:16])
	}

	return pinner
}

// pinnedID is the identifier this request claims to be pinned to, empty when it
// carries no pin.
func (p *sessionPinner) pinnedID(req *http.Request) string {
	cookie, err := req.Cookie(p.cookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}

// cookieFor returns the pin to hand back to the client, or nil when it already
// carries the right one. The pin lasts as long as the client's session: an
// expiry would only decide when the client rejoins the rotation, which the pool
// changing decides already.
func (p *sessionPinner) cookieFor(req *http.Request, target *Target) *http.Cookie {
	id := p.ids[target]
	if id == "" || id == p.pinnedID(req) {
		return nil
	}

	return &http.Cookie{
		Name:     p.cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
}

// pinnedTarget returns the healthy target this request is pinned to, or nil to
// let the usual rotation choose one.
//
// Reads served by a read-only replica are never pinned: a replica holds no
// per-instance session state, so pinning one would trade the read split away
// for nothing. Writes are pinned, and the writer-affinity cookie then keeps a
// client's follow-up reads on the writer it is pinned to.
//
// The caller must hold lb.lock: the healthy pools are read here.
func (lb *LoadBalancer) pinnedTarget(req *http.Request, reader bool) *Target {
	if lb.sessionAffinity == nil || ignoresSessionPin(req) {
		return nil
	}

	if reader && len(lb.readers) > 0 {
		return nil
	}

	id := lb.sessionAffinity.pinnedID(req)
	if id == "" {
		return nil
	}

	for _, target := range lb.writers {
		if lb.sessionAffinity.ids[target] == id {
			return target
		}
	}

	return nil
}

// pinSession arranges for the response to carry the pin for the target that
// served it. It returns the writer to serve through, which is the one it was
// given whenever there is nothing to pin.
func (lb *LoadBalancer) pinSession(w http.ResponseWriter, req *http.Request, target *Target) http.ResponseWriter {
	if lb.sessionAffinity == nil || target.ReadOnly() {
		return w
	}

	cookie := lb.sessionAffinity.cookieFor(req, target)

	// A retry may land on a different target than the attempt before it, so an
	// existing writer is re-pointed rather than wrapped again -- including at a
	// nil cookie, which would otherwise leave the failed attempt's pin in place.
	if pinned, ok := w.(*sessionAffinityWriter); ok {
		pinned.cookie = cookie
		return pinned
	}

	if cookie == nil {
		return w
	}

	return &sessionAffinityWriter{ResponseWriter: w, cookie: cookie}
}

// clearSessionPin drops a pin staged by an attempt that then failed, so that a
// client is not sent back to a target the proxy has just given up on.
func clearSessionPin(w http.ResponseWriter) {
	if pinned, ok := w.(*sessionAffinityWriter); ok {
		pinned.cookie = nil
	}
}

// ignoreSessionPin marks a request as having already been placed on its pinned
// target unsuccessfully, so that the next attempt rotates instead of choosing
// the same target again.
func ignoreSessionPin(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), contextKeyIgnoreSessionPin, true))
}

func ignoresSessionPin(req *http.Request) bool {
	ignore, _ := req.Context().Value(contextKeyIgnoreSessionPin).(bool)
	return ignore
}

// sessionAffinityWriter sets the pin cookie as the response headers go out, so
// that the target which actually served the request is the one pinned.
type sessionAffinityWriter struct {
	http.ResponseWriter
	cookie        *http.Cookie
	headerWritten bool
}

func (w *sessionAffinityWriter) WriteHeader(statusCode int) {
	if !w.headerWritten && w.cookie != nil {
		http.SetCookie(w.ResponseWriter, w.cookie)
	}
	w.headerWritten = true

	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *sessionAffinityWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(b)
}

func (w *sessionAffinityWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ResponseWriter does not implement http.Hijacker")
	}

	return hijacker.Hijack()
}

func (w *sessionAffinityWriter) Flush() {
	flusher, ok := w.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}
