package server

import "net/http"

// The Service side of the response cache: where it sits in the request path,
// and what separates one service's entries from another's. The cache itself
// lives in cache_middleware.go.

// SetCacheStore installs the shared response cache. It arrives after the service
// does -- services restored from the state file are built before the store is
// opened -- so the cache entry point is rebuilt rather than assumed.
func (s *Service) SetCacheStore(store CacheStore, leases CacheLeaseOptions) {
	s.cacheStore = store
	s.cacheLeases = leases
	s.cacheHandler = s.createCacheHandler(s.options)
}

func (s *Service) sendRequestToTarget(w http.ResponseWriter, r *http.Request) {
	// The idle gate lives here rather than beside the other checks, because this
	// is the first point a request is known to actually need the target. A cache
	// hit never reaches it, so serving stored responses does not wake a sleeping
	// container -- which is the whole reason to run both features on one service.
	//
	// Everything above still applies: this sits below the auth, allow-list, rate
	// limit and redirect gates, so none of those can spend a container start. It
	// is also still above target selection, and net/http does not read a request
	// body until the handler asks, so a request held here is handed on unread.
	handled, endIdleRequest := s.handleIdleRequest(w, r)
	if endIdleRequest != nil {
		defer endIdleRequest()
	}
	if handled {
		return
	}

	sendRequest := s.startLoadBalancerRequest(w, r)
	if sendRequest != nil {
		sendRequest()
	}
}

// createCacheHandler is the step between this service's checks and its load
// balancer. Without --cache it is the load balancer directly, so a service that
// does not cache pays nothing for the seam.
func (s *Service) createCacheHandler(options ServiceOptions) http.Handler {
	toTarget := http.HandlerFunc(s.sendRequestToTarget)
	if !options.Cache.Enabled {
		return toTarget
	}

	return WithCacheMiddleware(CacheConfig{
		Service: s.name,
		Options: options.Cache,
		Store:   s.cacheStore,
		Variant: s.cacheVariant,
		Leases:  s.cacheLeases,
	}, toTarget)
}

// cacheVariant keeps a rollout's responses out of the entries the stable targets
// populate. The two are running different versions of the application, so at the
// same URL they are simply different resources.
func (s *Service) cacheVariant(r *http.Request) string {
	s.serviceLock.RLock()
	defer s.serviceLock.RUnlock()

	if s.rollout != nil && s.rolloutController != nil && s.rolloutController.RequestUsesRolloutGroup(r) {
		return "rollout"
	}

	return ""
}
