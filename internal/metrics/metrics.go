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

type prometheusTracker struct {
	httpRequests     *prometheus.CounterVec
	httpDuration     *prometheus.HistogramVec
	inflightRequests *prometheus.GaugeVec

	// Certificate metrics
	certExpiry   *prometheus.GaugeVec
	certRenewals *prometheus.CounterVec
	certCount    *prometheus.GaugeVec
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
