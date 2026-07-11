package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	domainsRefreshPath  = "/.kamal-proxy/domains/refresh"
	preflightPathPrefix = "/.kamal-proxy/preflight/"

	// refreshMinInterval rate-limits refresh nudges; the poll interval remains
	// the source of truth so a lost nudge is only a latency hit.
	refreshMinInterval = 10 * time.Second
)

// WrapHandler mounts the refresh nudge and pre-flight probe endpoints ahead of
// the proxy's regular request handling.
func (dm *DynamicDomainManager) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == domainsRefreshPath:
			dm.handleRefresh(w, r)
		case strings.HasPrefix(r.URL.Path, preflightPathPrefix):
			dm.handlePreflight(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// Private

// handleRefresh accepts an authenticated nudge to re-poll all domain sources
// immediately. It carries no domain data: the poll stays the single source of
// truth, replays are harmless, and it works from any host.
func (dm *DynamicDomainManager) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Hidden unless a token is configured AND at least one service has a source
	if dm.config.RefreshToken == "" || !dm.HasSources() {
		http.NotFound(w, r)
		return
	}

	token, ok := bearerToken(r)
	if !ok || !tokensEqual(token, dm.config.RefreshToken) {
		slog.Warn("Rejected domain refresh request", "remote_addr", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	dm.mu.Lock()
	if time.Since(dm.lastRefresh) < refreshMinInterval {
		dm.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(int(refreshMinInterval.Seconds())))
		http.Error(w, "refresh requested too recently", http.StatusTooManyRequests)
		return
	}
	dm.lastRefresh = time.Now()
	dm.mu.Unlock()

	count := dm.RefreshAll()
	slog.Info("Domain refresh requested", "sources", count, "remote_addr", r.RemoteAddr)

	w.WriteHeader(http.StatusAccepted)
}

// handlePreflight serves the per-boot nonce used by the pre-issuance
// self-probe to confirm a domain routes back to this proxy.
func (dm *DynamicDomainManager) handlePreflight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != preflightPathPrefix+dm.preflightNonce {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(dm.preflightNonce))
}

func bearerToken(r *http.Request) (string, bool) {
	return strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// tokensEqual compares tokens in constant time, via digests so length is not
// leaked either.
func tokensEqual(a, b string) bool {
	digestA := sha256.Sum256([]byte(a))
	digestB := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(digestA[:], digestB[:]) == 1
}
