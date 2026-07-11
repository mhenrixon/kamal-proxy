package server

import (
	"cmp"
	"os"
	"path"
	"syscall"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

const (
	DefaultHttpPort  = 80
	DefaultHttpsPort = 443
)

type Config struct {
	Bind         string
	HttpPort     int
	HttpsPort    int
	MetricsPort  int
	HTTP3Enabled bool

	AlternateConfigDir string

	// ACME configuration for automatic certificate management
	ACMEEmail          string
	ACMEDirectory      string
	ACMEDNSProvider    acme.ProviderName
	ACMEPreferWildcard bool
	ACMEHTTPFallback   bool
}

func (c Config) SocketPath() string {
	return path.Join(c.runtimeDirectory(), "kamal-proxy.sock")
}

func (c Config) StatePath() string {
	return path.Join(c.dataDirectory(), "kamal-proxy.state")
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
