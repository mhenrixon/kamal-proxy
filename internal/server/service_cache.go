package server

import "net/http"

// The Service side of the response cache: where it sits in the request path,
// and what separates one service's entries from another's. The cache itself
// lives in cache_middleware.go.

// SetCacheStore installs the shared response cache. It arrives after the service
// does -- services restored from the state file are built before the store is
// opened -- so the cache entry point is rebuilt rather than assumed.
func (s *Service) SetCacheStore(store CacheStore) {
	s.cacheStore = store
	s.cacheHandler = s.createCacheHandler(s.options)
}

func (s *Service) sendRequestToTarget(w http.ResponseWriter, r *http.Request) {
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
