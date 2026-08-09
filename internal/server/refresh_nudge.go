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

// refreshMinInterval rate-limits refresh nudges; the poll interval remains
// the source of truth so a lost nudge is only a latency hit.
const refreshMinInterval = 10 * time.Second

// refreshNudge is the shared shape of the "re-poll now" endpoints: hidden
// unless configured, POST-only, bearer-token authenticated, rate limited.
// Both the domains and the redirects refresh handlers serve through it, so an
// ordering or status fix cannot drift between the two.
type refreshNudge struct {
	// Kind names the subsystem in log lines ("domains", "redirects").
	Kind string
	// Token authorizes the nudge; empty hides the endpoint.
	Token string
	// HasSources reports whether anything is configured to refresh; the
	// endpoint stays hidden otherwise.
	HasSources func() bool
	// TryClaim claims one rate-limited refresh slot; false answers 429.
	TryClaim func() bool
	// Refresh triggers the re-poll and returns how many sources were nudged.
	Refresh func() int
}

func (n refreshNudge) serve(w http.ResponseWriter, r *http.Request) {
	// Hidden first, whatever the method: a disabled endpoint must be
	// indistinguishable from an unknown path, and a 405 would reveal it.
	if n.Token == "" || !n.HasSources() {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, ok := bearerToken(r)
	if !ok || !tokensEqual(token, n.Token) {
		slog.Warn("Rejected refresh request", "kind", n.Kind, "remote_addr", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !n.TryClaim() {
		w.Header().Set("Retry-After", strconv.Itoa(int(refreshMinInterval.Seconds())))
		http.Error(w, "refresh requested too recently", http.StatusTooManyRequests)
		return
	}

	count := n.Refresh()
	slog.Info("Refresh requested", "kind", n.Kind, "sources", count, "remote_addr", r.RemoteAddr)

	w.WriteHeader(http.StatusAccepted)
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
