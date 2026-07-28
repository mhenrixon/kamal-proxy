package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	// DefaultTargetDialTimeout bounds establishing a connection to a target.
	// Without one there is no limit at all: a target whose IP blackholes SYNs
	// hangs the request until the OS gives up. ResponseTimeout cannot cover
	// this, as its clock only starts once the request has been written.
	DefaultTargetDialTimeout = time.Second * 30

	// DefaultTargetIdleConnTimeout expires pooled connections. Zero would mean
	// "never", which additionally disables the staleness check the transport
	// applies before handing a request to a pooled connection.
	DefaultTargetIdleConnTimeout = time.Second * 90
)

var ErrTargetOptionsInvalid = errors.New("target options invalid")

// poolSettings are the resolved connection pool settings for one target. Every
// zero in TargetOptions means "the proxy's default", so a service restored from
// a state file written before these options existed, or deployed by an older
// client over RPC, gets the same pool as a fresh deploy.
type poolSettings struct {
	MaxConns          int
	MaxIdleConns      int
	IdleConnTimeout   time.Duration
	DialTimeout       time.Duration
	DisableKeepAlives bool
}

// poolSettings resolves the pool knobs, applying the proxy's default wherever a
// value is absent. This has to happen server-side rather than in the cobra flag
// defaults: restoring saved state, rolling out, and older clients over RPC all
// bypass the CLI, and nothing defaults these values on load.
func (to TargetOptions) poolSettings() poolSettings {
	settings := poolSettings{
		MaxConns:          to.MaxConnsPerHost,
		MaxIdleConns:      to.MaxIdleConnsPerHost,
		IdleConnTimeout:   to.IdleConnTimeout,
		DialTimeout:       to.DialTimeout,
		DisableKeepAlives: to.DisableKeepAlives,
	}

	// Validate rejects negatives from a client, but saved state is never
	// validated, so clamp here rather than trusting the value.
	if settings.MaxConns < 0 {
		settings.MaxConns = 0
	}
	if settings.MaxIdleConns <= 0 {
		settings.MaxIdleConns = MaxIdleConnsPerHost
	}
	if settings.IdleConnTimeout <= 0 {
		settings.IdleConnTimeout = DefaultTargetIdleConnTimeout
	}
	if settings.DialTimeout <= 0 {
		settings.DialTimeout = DefaultTargetDialTimeout
	}

	return settings
}

// newProxyTransport builds the connection pool for one of a target's proxy
// handlers. A target has one handler per response timeout in play, so each
// setting here applies 1 + len(TargetOptions.PathResponseTimeouts) times over.
//
// Targets are always plain http -- parseTargetURL supplies the scheme and
// hostRegex rejects any the caller tries to pass -- so setting DialContext
// dropping this transport to HTTP/1 only costs nothing, and saves configuring
// an http2.Transport per pool that could never negotiate h2. If https targets
// are ever supported this MUST also set ForceAttemptHTTP2 and a
// TLSHandshakeTimeout, which is zero ("no timeout") here for the same reason.
// TestParseTargetURL_AlwaysUsesHTTPScheme guards that assumption.
//
// Proxy is deliberately left nil: HTTP_PROXY and NO_PROXY must not apply to the
// target leg. Do not refactor this toward http.DefaultTransport.Clone().
func newProxyTransport(options TargetOptions, responseTimeout time.Duration) *http.Transport {
	settings := options.poolSettings()

	// Dialer.KeepAlive is deliberately left at zero, which is the stdlib's 15s
	// idle / 15s interval / 9 probes -- what this proxy has always used, and more
	// aggressive than http.DefaultTransport's explicit 30s. A negative value
	// would silently disable TCP dead-peer detection.
	dialer := &net.Dialer{Timeout: settings.DialTimeout}

	return &http.Transport{
		DialContext:           dialer.DialContext,
		MaxConnsPerHost:       settings.MaxConns,
		MaxIdleConnsPerHost:   settings.MaxIdleConns,
		IdleConnTimeout:       settings.IdleConnTimeout,
		DisableKeepAlives:     settings.DisableKeepAlives,
		ResponseHeaderTimeout: responseTimeout,
	}
}

// Validate checks the target options a client can get wrong. Only the pool
// settings are range-checked: everything else is either bounded by its flag
// type or normalized at construction.
func (to TargetOptions) Validate() error {
	if to.MaxConnsPerHost < 0 {
		return fmt.Errorf("%w: target-max-conns cannot be negative", ErrTargetOptionsInvalid)
	}
	if to.MaxIdleConnsPerHost < 0 {
		return fmt.Errorf("%w: target-max-idle-conns cannot be negative", ErrTargetOptionsInvalid)
	}
	if to.IdleConnTimeout < 0 {
		return fmt.Errorf("%w: target-idle-conn-timeout cannot be negative", ErrTargetOptionsInvalid)
	}
	if to.DialTimeout < 0 {
		return fmt.Errorf("%w: target-dial-timeout cannot be negative", ErrTargetOptionsInvalid)
	}

	return nil
}
