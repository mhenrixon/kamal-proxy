package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type tracker interface {
	TrackRequest(service, method string, status int, duration time.Duration)
	AddInflightRequest(service string)
	SubtractInflightRequest(service string)
	SetCertificateExpiry(domain string, isWildcard bool, expiryTime time.Time)
	IncCertificateRenewals(domain string, success bool)
	SetCertificateCount(total, wildcard, http01 int)
	TrackCacheEvent(service, result string)
	TrackCacheRefusal(service, reason string)
	TrackCacheLease(service, outcome string)
	TrackCacheLeaseWait(service, outcome string)
	TrackCacheEviction(service, state string)
}

var Tracker tracker = &nullTracker{}

func Enable() http.Handler {
	Tracker = NewPrometheusTracker()
	return promhttp.Handler()
}

type nullTracker struct{}

func (nullTracker) TrackRequest(service, method string, status int, dur time.Duration)        {}
func (nullTracker) AddInflightRequest(service string)                                         {}
func (nullTracker) SubtractInflightRequest(service string)                                    {}
func (nullTracker) SetCertificateExpiry(domain string, isWildcard bool, expiryTime time.Time) {}
func (nullTracker) IncCertificateRenewals(domain string, success bool)                        {}
func (nullTracker) SetCertificateCount(total, wildcard, http01 int)                           {}
func (nullTracker) TrackCacheEvent(service, result string)                                    {}
func (nullTracker) TrackCacheRefusal(service, reason string)                                  {}
func (nullTracker) TrackCacheLease(service, outcome string)                                   {}
func (nullTracker) TrackCacheLeaseWait(service, outcome string)                               {}
func (nullTracker) TrackCacheEviction(service, state string)                                  {}

type prometheusTracker struct {
	httpRequests     *prometheus.CounterVec
	httpDuration     *prometheus.HistogramVec
	inflightRequests *prometheus.GaugeVec

	// Certificate metrics
	certExpiry   *prometheus.GaugeVec
	certRenewals *prometheus.CounterVec
	certCount    *prometheus.GaugeVec

	// Response cache metrics
	cacheEvents     *prometheus.CounterVec
	cacheRefusals   *prometheus.CounterVec
	cacheLeases     *prometheus.CounterVec
	cacheLeaseWaits *prometheus.CounterVec
	cacheEvictions  *prometheus.CounterVec
}

func NewPrometheusTracker() *prometheusTracker {
	tracker := &prometheusTracker{
		httpRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "http_requests_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "HTTP requests processed, labeled by service, status code and method.",
			},
			[]string{"service", "method", "status"},
		),

		httpDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:      "http_request_duration_seconds",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Duration of HTTP requests, labeled by service, status code and method.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"service", "method", "status"},
		),

		inflightRequests: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "http_in_flight_requests",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Number of in-flight HTTP requests, labeled by service.",
			},
			[]string{"service"},
		),

		certExpiry: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "certificate_expiry_timestamp_seconds",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Unix timestamp when certificate expires, labeled by domain and type.",
			},
			[]string{"domain", "type"},
		),

		certRenewals: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "certificate_renewals_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Number of certificate renewal attempts, labeled by domain and result.",
			},
			[]string{"domain", "result"},
		),

		cacheEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "cache_events_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Response cache outcomes, labeled by service and result (hit, miss, stale, coalesced, store, error).",
			},
			[]string{"service", "result"},
		),

		cacheRefusals: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "cache_refusals_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Responses the cache declined to store, labeled by service and reason. A service sitting at 100% miss is explained here.",
			},
			[]string{"service", "reason"},
		),

		cacheLeases: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "cache_leases_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Cross-node cache fetch arbitration, labeled by service and outcome (acquired, taken, unavailable, deferred). 'taken' counts origin fetches the fleet did not make.",
			},
			[]string{"service", "outcome"},
		),

		cacheLeaseWaits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "cache_lease_waits_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "How waits on another proxy's fetch ended, labeled by service and outcome (served, released, expired, abandoned). Rising 'expired' means --cache-lease-wait is short for this origin.",
			},
			[]string{"service", "outcome"},
		),

		cacheEvictions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "cache_evictions_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Cache entries dropped to stay inside --cache-memory-size, labeled by service and state (fresh, stale). Rising 'fresh' is what says the budget is too small; 'stale' alone is a cache doing its job.",
			},
			[]string{"service", "state"},
		),

		certCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "certificates_total",
				Namespace: "kamal",
				Subsystem: "proxy",
				Help:      "Number of managed certificates, labeled by type.",
			},
			[]string{"type"},
		),
	}

	prometheus.MustRegister(
		tracker.httpRequests,
		tracker.httpDuration,
		tracker.inflightRequests,
		tracker.certExpiry,
		tracker.certRenewals,
		tracker.certCount,
		tracker.cacheEvents,
		tracker.cacheRefusals,
		tracker.cacheLeases,
		tracker.cacheLeaseWaits,
		tracker.cacheEvictions,
	)

	return tracker
}

func (p *prometheusTracker) TrackRequest(service, method string, status int, duration time.Duration) {
	method = normalizeMethod(method)
	statusString := strconv.Itoa(status)

	p.httpRequests.WithLabelValues(service, method, statusString).Inc()
	p.httpDuration.WithLabelValues(service, method, statusString).Observe(duration.Seconds())
}

func (p *prometheusTracker) AddInflightRequest(service string) {
	p.inflightRequests.WithLabelValues(service).Inc()
}

func (p *prometheusTracker) SubtractInflightRequest(service string) {
	p.inflightRequests.WithLabelValues(service).Dec()
}

func (p *prometheusTracker) SetCertificateExpiry(domain string, isWildcard bool, expiryTime time.Time) {
	certType := "individual"
	if isWildcard {
		certType = "wildcard"
	}
	p.certExpiry.WithLabelValues(domain, certType).Set(float64(expiryTime.Unix()))
}

func (p *prometheusTracker) IncCertificateRenewals(domain string, success bool) {
	result := "success"
	if !success {
		result = "failure"
	}
	p.certRenewals.WithLabelValues(domain, result).Inc()
}

func (p *prometheusTracker) SetCertificateCount(total, wildcard, http01 int) {
	p.certCount.WithLabelValues("total").Set(float64(total))
	p.certCount.WithLabelValues("wildcard").Set(float64(wildcard))
	p.certCount.WithLabelValues("http01").Set(float64(http01))
}

func (p *prometheusTracker) TrackCacheEvent(service, result string) {
	p.cacheEvents.WithLabelValues(service, result).Inc()
}

func (p *prometheusTracker) TrackCacheRefusal(service, reason string) {
	p.cacheRefusals.WithLabelValues(service, reason).Inc()
}

func (p *prometheusTracker) TrackCacheLease(service, outcome string) {
	p.cacheLeases.WithLabelValues(service, outcome).Inc()
}

func (p *prometheusTracker) TrackCacheLeaseWait(service, outcome string) {
	p.cacheLeaseWaits.WithLabelValues(service, outcome).Inc()
}

func (p *prometheusTracker) TrackCacheEviction(service, state string) {
	p.cacheEvictions.WithLabelValues(service, state).Inc()
}

// Private

func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost,
		http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}
