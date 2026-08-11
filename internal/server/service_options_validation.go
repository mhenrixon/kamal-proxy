package server

import (
	"fmt"
	"net/url"
	"strings"
)

// Validators for the fork-only ServiceOptions fields, kept out of service.go so
// that file stays under the size ceiling and the upstream merge surface stays
// localized.

func (so ServiceOptions) validateInterceptErrorStatuses() error {
	for _, status := range so.InterceptErrorStatuses {
		if status < 400 || status > 599 {
			return fmt.Errorf("%w: intercept-errors must be a 4xx or 5xx status code, got %d", ErrServiceOptionsInvalid, status)
		}
	}

	return nil
}

func (so ServiceOptions) validateDynamicRedirects() error {
	if so.RedirectsSource == "" {
		if so.RedirectsInterval != 0 {
			return fmt.Errorf("%w: redirects-interval requires redirects-source", ErrServiceOptionsInvalid)
		}
		return nil
	}

	// A prefix check alone would accept "https://" or "http://:8080", which
	// pass the deploy and then fail every poll; a malformed source should fail
	// on the operator's terminal instead.
	if !strings.HasPrefix(so.RedirectsSource, "/") {
		parsed, err := url.Parse(so.RedirectsSource)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return fmt.Errorf("%w: redirects-source must be a path or an http(s) URL: %q", ErrServiceOptionsInvalid, so.RedirectsSource)
		}
	}

	if so.RedirectsInterval != 0 && so.RedirectsInterval < MinRedirectsInterval {
		return fmt.Errorf("%w: redirects-interval must be at least %s", ErrServiceOptionsInvalid, MinRedirectsInterval)
	}

	return nil
}

// validateACMEDirectory rejects a per-service ACME directory that is not an
// http(s) URL. The deploy CLI only ever sets the well-known staging constant,
// but the field arrives over RPC and would otherwise fail much later, inside
// an ACME order.
func (so ServiceOptions) validateACMEDirectory() error {
	if so.ACMEDirectory == "" {
		return nil
	}

	parsed, err := url.Parse(so.ACMEDirectory)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return fmt.Errorf("%w: acme directory must be an http(s) URL: %q", ErrServiceOptionsInvalid, so.ACMEDirectory)
	}

	return nil
}

func (so ServiceOptions) validateDynamicDomains() error {
	if so.TLSDomainsSource == "" {
		if so.TLSDomainsBatchSize != 0 {
			return fmt.Errorf("%w: tls-domains-batch-size requires tls-domains-source", ErrServiceOptionsInvalid)
		}
		if so.TLSDomainsInterval != 0 {
			return fmt.Errorf("%w: tls-domains-interval requires tls-domains-source", ErrServiceOptionsInvalid)
		}
		return nil
	}

	if !so.TLSEnabled {
		return fmt.Errorf("%w: tls-domains-source requires TLS to be enabled", ErrServiceOptionsInvalid)
	}

	// Both provision certificates for hosts that aren't known at deploy time, but
	// through different managers -- only one of them can serve the handshake.
	if so.TLSOnDemandURL != "" {
		return fmt.Errorf("%w: tls-domains-source cannot be combined with tls-on-demand-url", ErrServiceOptionsInvalid)
	}

	// Dynamic domains are routed via the host-less catch-all binding; a
	// host-scoped service would issue certificates that can never be served.
	if so.HasConfiguredHosts() {
		return fmt.Errorf("%w: tls-domains-source requires the service to be the catch-all (no --host)", ErrServiceOptionsInvalid)
	}

	if !validDomainSource(so.TLSDomainsSource) {
		return fmt.Errorf("%w: tls-domains-source must be a path or an http(s) URL: %q", ErrServiceOptionsInvalid, so.TLSDomainsSource)
	}

	if so.TLSDomainsBatchSize < 0 || so.TLSDomainsBatchSize > MaxTLSDomainsBatchSize {
		return fmt.Errorf("%w: tls-domains-batch-size must be between 1 and %d", ErrServiceOptionsInvalid, MaxTLSDomainsBatchSize)
	}

	if so.TLSDomainsInterval != 0 && so.TLSDomainsInterval < MinTLSDomainsInterval {
		return fmt.Errorf("%w: tls-domains-interval must be at least %s", ErrServiceOptionsInvalid, MinTLSDomainsInterval)
	}

	return nil
}
