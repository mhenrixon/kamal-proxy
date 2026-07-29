package server

import "fmt"

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
