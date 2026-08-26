package server

import (
	"cmp"
	"errors"
	"log/slog"
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

	// DockerSocketPath enables scale-to-zero by giving the proxy a container
	// runtime to stop and start with. Empty (the default) leaves the feature
	// unavailable, and a deploy asking for --sleep-after is refused rather than
	// accepted and silently never acted on.
	//
	// Reaching this socket is root-equivalent on the host, which is why it is
	// opt-in and off by default.
	DockerSocketPath string

	// MinTLS is the lowest TLS version the HTTPS listener will negotiate,
	// written as "1.2" or "1.3". Empty means 1.2, which is also Go's own
	// minimum, so this setting can only ever narrow what the listener accepts -
	// ParseMinTLSVersion refuses TLS 1.0 and 1.1 outright.
	MinTLS string

	// MetricsAllowIPs restricts the metrics endpoint to these addresses and CIDR
	// ranges. Empty (the default) serves everyone that can reach the port.
	MetricsAllowIPs []string

	// LogFormat selects the handler every log line - the access log included -
	// is written through, either "json" or "text". Empty means json, which is
	// what kamal-proxy has always written.
	LogFormat string

	// TraceContext decides what the proxy does with the W3C traceparent header:
	// "off", "propagate" or "generate". Empty means propagate.
	TraceContext string

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

	// CacheStore is where responses cached by services deployed with --cache
	// live: "memory" (the default) for a per-node cache, or a redis:// or
	// rediss:// URL every proxy in a fleet can share. A service without --cache
	// never touches it.
	CacheStore string
	// CacheStoreTimeout bounds each shared-store operation. Zero means
	// DefaultCacheStoreTimeout.
	CacheStoreTimeout time.Duration
	// CacheMemorySize caps the in-process store. Zero means
	// DefaultCacheMemorySize.
	CacheMemorySize int64
	// CacheLeaseTTL and CacheLeaseWait configure the cross-node single flight.
	// They have an effect only with a shared --cache-store. Zero means the
	// default; negative switches the piece off.
	CacheLeaseTTL  time.Duration
	CacheLeaseWait time.Duration

	AlternateConfigDir string

	// ACME configuration for automatic certificate management
	ACMEEmail          string
	ACMEDirectory      string
	ACMEDNSProvider    acme.ProviderName
	ACMEPreferWildcard bool
	ACMEHTTPFallback   bool

	// ACMEReleaseProbeInterval is how often a held domain is re-probed so its
	// hold can be lifted as soon as it routes here again — the difference
	// between a DNS cutover costing a probe interval and costing a backoff
	// step. Zero uses the default; negative disables release probing.
	ACMEReleaseProbeInterval time.Duration

	// ACMEDNSProviderZones maps DNS zones to the provider answering DNS-01
	// for them, for fleets whose zones live at different DNS hosts.
	// ACMEDNSProvider stays the default for unmatched zones.
	ACMEDNSProviderZones map[string]acme.ProviderName
}

// SocketPath is recreated on every boot, so the name is free to move. The
// legacy environment override is still honored: the gem sets KAMAL_PROXY_SOCKET
// on containers it booted before the rename, and a running proxy is reached
// over whatever socket it opened.
func (c Config) SocketPath() string {
	return cmp.Or(
		os.Getenv("DASH_PROXY_SOCKET"),
		os.Getenv("KAMAL_PROXY_SOCKET"),
		path.Join(c.runtimeDirectory(), "dash-proxy.sock"),
	)
}

// StatePath is the routing table, always under the current name. Recovering a
// pre-rename table is AdoptLegacyState's job, called once at boot.
func (c Config) StatePath() string {
	return path.Join(c.dataDirectory(), "dash-proxy.state")
}

// LegacyStatePath is the pre-rename routing table, which the gem's volume copy
// carries into the new volume verbatim.
func (c Config) LegacyStatePath() string {
	return path.Join(c.dataDirectory(), "kamal-proxy.state")
}

// AdoptLegacyState seeds the current state file from the pre-rename one when
// the data directory has only the old name — the shape the gem's volume copy
// leaves behind. Without it the proxy boots with an empty routing table and
// every service has to be re-registered by a deploy, which is an outage rather
// than a migration.
//
// It copies rather than renames, so the legacy file survives: an operator who
// rolls back to a pre-rename image must still find the table where that image
// looks for it. Stage 3d removes both the copy and the leftover.
//
// Doing this once at boot, rather than teaching StatePath to return whichever
// file exists, is what makes the host converge. Reading *and writing* the old
// name would leave every upgraded host on the legacy filename forever, and the
// fallback could never be retired.
func (c Config) AdoptLegacyState() error {
	current, legacy := c.StatePath(), c.LegacyStatePath()

	if _, err := os.Stat(current); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	contents, err := os.ReadFile(legacy)
	if errors.Is(err, os.ErrNotExist) {
		return nil // A first boot, not an upgrade.
	} else if err != nil {
		return err
	}

	if err := os.WriteFile(current, contents, 0o600); err != nil {
		return err
	}

	slog.Info("Adopted the pre-rename routing table", "from", legacy, "to", current)
	return nil
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

// CertStorePaths names the pieces of the certificate estate for export and
// restore.
func (c Config) CertStorePaths() CertStorePaths {
	return CertStorePaths{
		CertsPath:               c.CertificatePath(),
		ACMEStatePath:           c.ACMEStatePath(),
		DynamicDomainsStatePath: c.DynamicDomainsStatePath(),
	}
}

func (c Config) DynamicRedirectsStatePath() string {
	return path.Join(c.dataDirectory(), "dynamic-redirects.state")
}

// SANCertManagerConfig returns the configuration for the certificate manager,
// which is the proxy's only ACME system: one account, one cache, one allowlist,
// both challenge types.
func (c Config) SANCertManagerConfig() SANCertManagerConfig {
	directory := c.ACMEDirectory
	if directory == "" {
		directory = acme.DefaultProductionDirectory
	}

	return SANCertManagerConfig{
		Email:            c.ACMEEmail,
		Directory:        directory,
		DNSProvider:      c.ACMEDNSProvider,
		DNSProviderZones: c.ACMEDNSProviderZones,
		PreferWildcard:   c.ACMEPreferWildcard,
		HTTPFallback:     c.ACMEHTTPFallback,
		CachePath:        c.CertificatePath(),
		StatePath:        c.ACMEStatePath(),
	}
}

func (c Config) ResponseCacheLeaseOptions() CacheLeaseOptions {
	return CacheLeaseOptions{TTL: c.CacheLeaseTTL, Wait: c.CacheLeaseWait}
}

func (c Config) ResponseCacheStoreConfig() CacheStoreConfig {
	return CacheStoreConfig{
		URL:        c.CacheStore,
		MemorySize: c.CacheMemorySize,
		Timeout:    c.CacheStoreTimeout,
	}
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

	dir := path.Join(home, ".config", "dash-proxy")

	err = os.MkdirAll(dir, syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR)
	if err != nil {
		dir = os.TempDir()
	}

	return dir
}
