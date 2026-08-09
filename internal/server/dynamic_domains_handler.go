package server

import (
	"net/http"
	"strings"
	"time"
)

const (
	domainsRefreshPath  = "/.kamal-proxy/domains/refresh"
	preflightPathPrefix = "/.kamal-proxy/preflight/"
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
	refreshNudge{
		Kind:       "domains",
		Token:      dm.config.RefreshToken,
		HasSources: dm.HasSources,
		TryClaim:   dm.tryClaimRefresh,
		Refresh:    dm.RefreshAll,
	}.serve(w, r)
}

func (dm *DynamicDomainManager) tryClaimRefresh() bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if time.Since(dm.lastRefresh) < refreshMinInterval {
		return false
	}
	dm.lastRefresh = time.Now()
	return true
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
