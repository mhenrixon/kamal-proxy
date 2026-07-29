package server

import "net/http"

const (
	// pingPath answers liveness probes for the proxy itself. It lives in the
	// same reserved namespace as the dynamic-domain endpoints
	// (dynamic_domains_handler.go), but is mounted unconditionally: an operator
	// probing a proxy with nothing deployed is exactly the case this exists for.
	pingPath = "/.kamal-proxy/ping"

	pingBody = "OK\n"
)

// pingResponse is written straight from this shared backing array, so answering
// a probe allocates nothing beyond what net/http needs for the response itself.
var pingResponse = []byte(pingBody)

// WithPingMiddleware answers liveness probes ahead of the proxy's regular
// request handling.
//
// It is mounted outermost in Server.buildHandler, which is what keeps probes out
// of the access log: the logging middleware never sees them, rather than being
// taught to skip them. Probes therefore also carry no request ID and never
// render an error page — the tradeoff for an endpoint a monitor hits every few
// seconds forever.
//
// Liveness here means "this process is serving", nothing more. There is
// deliberately no readiness variant: RestoreLastSavedState runs before Start
// opens a listener, and BeginDrain closes the listeners rather than keeping them
// up in a not-ready state, so a readiness probe on this listener could only ever
// return 200. Whether the proxy accepts a connection at all is the more
// informative signal, and monitors already have it.
func WithPingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pingPath {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		w.Write(pingResponse)
	})
}
