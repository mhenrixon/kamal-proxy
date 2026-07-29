package server

import (
	"cmp"
	"os"
	"path"
	"syscall"
	"time"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

const (
	DefaultHttpPort  = 80
	DefaultHttpsPort = 443

	// DefaultReadHeaderTimeout bounds how long a client may take to send its
	// request headers. Without it a handful of slowloris connections can hold
	// listener resources open indefinitely.
	DefaultReadHeaderTimeout = 30 * time.Second

	// DefaultIdleTimeout bounds how long an established keep-alive connection
	// may sit without carrying a request.
	DefaultIdleTimeout = 60 * time.Second

	// DefaultReadTimeout is disabled: it caps the time to read the *entire*
	// request, so any non-zero value truncates slow or large uploads passing
	// through the proxy.
	DefaultReadTimeout = 0

	// DefaultWriteTimeout is disabled: it caps the time to write the *entire*
	// response, so any non-zero value truncates SSE streams (see the
	// text/event-stream bypass in response_buffer_middleware.go) and long
	// downloads.
	DefaultWriteTimeout = 0

	// DefaultShutdownTimeout bounds how long a stopping server waits for
	// in-flight requests to drain before closing their connections.
	DefaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	Bind         string
	HttpPort     int
	HttpsPort    int
	MetricsPort  int
	HTTP3Enabled bool

	// MinTLS is the lowest TLS version the HTTPS listener will negotiate,
	// written as "1.2" or "1.3". Empty means 1.2, which is also Go's own
	// minimum, so this setting can only ever narrow what the listener accepts -
	// ParseMinTLSVersion refuses TLS 1.0 and 1.1 outright.
	MinTLS string

	// MetricsAllowIPs restricts the metrics endpoint to these addresses and CIDR
	// ranges. Empty (the default) serves everyone that can reach the port.
	MetricsAllowIPs []string

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	ReusePort         bool

	// ProxyProtocol accepts PROXY protocol v1/v2 preambles on the HTTP and
	// HTTPS listeners, so client addresses survive an L4 load balancer hop.
	ProxyProtocol bool

	// ProxyProtocolAllowIPs restricts which peers may assert a client address
	// via a PROXY preamble to these addresses and CIDR ranges. Empty (the
	// default) trusts every peer that can reach the port.
	ProxyProtocolAllowIPs []string

	AlternateConfigDir string

	// ACME configuration for automatic certificate management
	ACMEEmail          string
	ACMEDirectory      string
	ACMEDNSProvider    acme.ProviderName
	ACMEPreferWildcard bool
	ACMEHTTPFallback   bool
}

func (c Config) SocketPath() string {
	return cmp.Or(os.Getenv("KAMAL_PROXY_SOCKET"), path.Join(c.runtimeDirectory(), "kamal-proxy.sock"))
}

func (c Config) StatePath() string {
	return path.Join(c.dataDirectory(), "kamal-proxy.state")
}

// StateBackupPath is the last-known-good copy of StatePath, written after each
// clean restore and used to recover from a torn or corrupted state file.
func (c Config) StateBackupPath() string {
	return c.StatePath() + ".bak"
}

func (c Config) CertificatePath() string {
	return path.Join(c.dataDirectory(), "certs")
}

func (c Config) ACMEStatePath() string {
	return path.Join(c.dataDirectory(), "acme.state")
}

func (c Config) DynamicDomainsStatePath() string {
	return path.Join(c.dataDirectory(), "dynamic-domains.state")
}

func (c Config) CertificateStatePath() string {
	return path.Join(c.dataDirectory(), "certificates.state")
}

// CertificateRegistryConfig returns the configuration for the certificate registry
func (c Config) CertificateRegistryConfig() CertificateRegistryConfig {
	directory := c.ACMEDirectory
	if directory == "" {
		directory = acme.DefaultProductionDirectory
	}

	return CertificateRegistryConfig{
		Email:          c.ACMEEmail,
		Directory:      directory,
		DNSProvider:    c.ACMEDNSProvider,
		PreferWildcard: c.ACMEPreferWildcard,
		HTTPFallback:   c.ACMEHTTPFallback,
		CachePath:      c.CertificatePath(),
		StatePath:      c.CertificateStatePath(),
	}
}

// HasACMEConfig returns true if ACME is configured
func (c Config) HasACMEConfig() bool {
	return c.ACMEEmail != "" && (c.ACMEDNSProvider != "" || c.ACMEHTTPFallback)
}

// Private

func (c Config) runtimeDirectory() string {
	return cmp.Or(os.Getenv("XDG_RUNTIME_DIR"), os.TempDir())
}

func (c Config) dataDirectory() string {
	return cmp.Or(c.AlternateConfigDir, c.defaultDataDirectory())
}

func (c Config) defaultDataDirectory() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}

	dir := path.Join(home, ".config", "kamal-proxy")

	err = os.MkdirAll(dir, syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR)
	if err != nil {
		dir = os.TempDir()
	}

	return dir
}
