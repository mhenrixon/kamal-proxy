package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

const (
	healthCheckUserAgent = "kamal-proxy"
)

var (
	ErrorHealthCheckRequestTimedOut  = errors.New("request timed out")
	ErrorHealthCheckUnexpectedStatus = errors.New("unexpected status")
)

type HealthCheckConsumer interface {
	HealthCheckCompleted(success bool)
}

// initialHealthCheckDelay is where the retry starts before doubling toward the
// configured interval. Small enough that a container which is listening almost
// immediately is noticed almost immediately.
const initialHealthCheckDelay = 50 * time.Millisecond

type HealthCheck struct {
	consumer HealthCheckConsumer
	endpoint *url.URL
	interval time.Duration
	timeout  time.Duration
	host     string

	ctx    context.Context
	cancel context.CancelFunc

	// becameHealthy latches on the first successful probe. Until then the retry
	// runs on a short backoff; afterwards the configured interval governs.
	becameHealthy atomic.Bool
}

func NewHealthCheck(consumer HealthCheckConsumer, endpoint *url.URL, interval time.Duration, timeout time.Duration, host string) *HealthCheck {
	ctx, cancel := context.WithCancel(context.Background())

	hc := &HealthCheck{
		consumer: consumer,
		endpoint: endpoint,
		interval: interval,
		timeout:  timeout,
		host:     host,

		ctx:    ctx,
		cancel: cancel,
	}

	go hc.run()
	return hc
}

func (hc *HealthCheck) Close() {
	hc.cancel()
}

// Private

// run probes immediately, then retries on a short backoff until the target first
// answers, and only then settles to the configured interval.
//
// The backoff exists because a target is routinely not listening yet at the
// moment we first look: `docker start` returns when the container process is
// created, not when the application is accepting connections. Measured on a real
// daemon, the immediate probe was refused and the next one came a full interval
// later -- 1009ms of pure waiting inside a 1154ms cold wake, for a container
// whose app was ready almost at once. A deploy pays the same tax.
//
// Once a target is healthy the configured interval governs, so a running target
// is not probed any harder than before.
func (hc *HealthCheck) run() {
	hc.check()

	timer := time.NewTimer(hc.nextDelay(initialHealthCheckDelay))
	defer timer.Stop()

	delay := initialHealthCheckDelay

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-timer.C:
			hc.check()

			if hc.becameHealthy.Load() {
				delay = hc.interval
			} else {
				delay = min(delay*2, hc.interval)
			}

			timer.Reset(hc.nextDelay(delay))
		}
	}
}

// nextDelay never returns more than the configured interval, so a proxy
// configured to probe quickly is not slowed down by the backoff.
func (hc *HealthCheck) nextDelay(delay time.Duration) time.Duration {
	return min(delay, hc.interval)
}

func (hc *HealthCheck) check() {
	ctx, cancel := context.WithTimeout(hc.ctx, hc.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hc.endpoint.String(), nil)
	if err != nil {
		hc.reportResult(false, err)
		return
	}

	req.Header.Set("User-Agent", healthCheckUserAgent)

	if hc.host != "" {
		req.Host = hc.host
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			err = ErrorHealthCheckRequestTimedOut
		}
		hc.reportResult(false, err)
		return
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		hc.reportResult(false, fmt.Errorf("%w (%d)", ErrorHealthCheckUnexpectedStatus, resp.StatusCode))
		return
	}

	hc.reportResult(true, nil)
}

func (hc *HealthCheck) reportResult(success bool, err error) {
	if !success {
		slog.Info("Healthcheck failed", "url", hc.endpoint.String(), "error", err)
	} else {
		hc.becameHealthy.Store(true)
	}

	hc.consumer.HealthCheckCompleted(success)
}
