package server

import (
	"net/http"
	"time"
)

const redirectsRefreshPath = "/.kamal-proxy/redirects/refresh"

// WrapHandler mounts the redirects refresh nudge ahead of the proxy's regular
// request handling, mirroring the domains refresh endpoint.
func (dm *DynamicRedirectManager) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == redirectsRefreshPath {
			dm.handleRefresh(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Private

// handleRefresh accepts an authenticated nudge to re-poll all redirects
// sources immediately. It carries no redirect data: the poll stays the single
// source of truth, replays are harmless, and it works from any host.
func (dm *DynamicRedirectManager) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshNudge{
		Kind:       "redirects",
		Token:      dm.config.RefreshToken,
		HasSources: dm.HasSources,
		TryClaim:   dm.tryClaimRefresh,
		Refresh:    dm.RefreshAll,
	}.serve(w, r)
}

func (dm *DynamicRedirectManager) tryClaimRefresh() bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if time.Since(dm.lastRefresh) < refreshMinInterval {
		return false
	}
	dm.lastRefresh = time.Now()
	return true
}
