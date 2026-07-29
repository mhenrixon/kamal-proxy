package server

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// DefaultMinTLSVersion is the minimum version the HTTPS listener negotiates
// when --min-tls is not given. It matches Go's own server-side minimum, so the
// default states an intent rather than changing behavior.
const DefaultMinTLSVersion = "1.2"

// ParseMinTLSVersion maps a --min-tls value onto a crypto/tls version constant.
//
// Only 1.2 and 1.3 are accepted. The flag exists to narrow what the listener
// will negotiate for a compliance scanner, never to widen it: Go already
// refuses TLS 1.0 and 1.1, and accepting them here would make a hardening flag
// the only way to downgrade the proxy. An empty value means the default, so an
// unset or blank MIN_TLS boots instead of failing.
func ParseMinTLSVersion(value string) (uint16, error) {
	if strings.TrimSpace(value) == "" {
		return tls.VersionTLS12, nil
	}

	switch normalized := normalizeTLSVersion(value); normalized {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	case "1.0", "1.1":
		return 0, fmt.Errorf("min-tls: TLS %s cannot be enabled; the lowest accepted minimum is %s", normalized, DefaultMinTLSVersion)
	default:
		return 0, fmt.Errorf("min-tls: %q is not a TLS version; use %s or 1.3", value, DefaultMinTLSVersion)
	}
}

// normalizeTLSVersion reduces the spellings operators actually type - and the
// tls1_2 form used by basecamp/kamal-proxy#199 - to a bare "1.2"/"1.3", so a
// config written for upstream keeps working here.
func normalizeTLSVersion(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))

	for _, prefix := range []string{"tlsv", "tls"} {
		if trimmed, found := strings.CutPrefix(normalized, prefix); found {
			normalized = trimmed
			break
		}
	}

	return strings.ReplaceAll(normalized, "_", ".")
}
