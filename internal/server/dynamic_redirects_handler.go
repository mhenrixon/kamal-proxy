package server

import (
	"log/slog"
	"net/http"
	"strconv"
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
		slog.Warn("Rejected redirects refresh request", "remote_addr", r.RemoteAddr)
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
	slog.Info("Redirects refresh requested", "sources", count, "remote_addr", r.RemoteAddr)

	w.WriteHeader(http.StatusAccepted)
}
