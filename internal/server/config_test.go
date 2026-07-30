package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

func TestConfig_StateBackupPathSitsBesideStatePath(t *testing.T) {
	config := Config{AlternateConfigDir: t.TempDir()}

	assert.Equal(t, config.StatePath()+".bak", config.StateBackupPath())
	assert.Equal(t, filepath.Dir(config.StatePath()), filepath.Dir(config.StateBackupPath()))
}

func TestConfig_StatePathHonorsAlternateConfigDir(t *testing.T) {
	dir := t.TempDir()
	config := Config{AlternateConfigDir: dir}

	assert.Equal(t, filepath.Join(dir, "kamal-proxy.state"), config.StatePath())
	assert.Equal(t, filepath.Join(dir, "certs"), config.CertificatePath())
}

func TestConfig_SocketPathHonorsEnvOverride(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "custom.sock")
	t.Setenv("KAMAL_PROXY_SOCKET", socketPath)

	config := Config{}
	assert.Equal(t, socketPath, config.SocketPath())
}

// Everything ACME writes -- the account key, the certificates, the manager's
// state -- has to land inside the directory the container image creates and the
// gem mounts as a volume, or a restart loses the account and re-orders every
// certificate. There is deliberately no separate knob for the cache path: it is
// derived from the data directory, which --data-dir already moves as a unit.
func TestConfig_ACMEStorageLivesInsideTheDataDirectory(t *testing.T) {
	dir := t.TempDir()
	config := Config{AlternateConfigDir: dir, ACMEEmail: "admin@example.com"}

	acmeConfig := config.SANCertManagerConfig()

	assert.Equal(t, filepath.Join(dir, "certs"), acmeConfig.CachePath)
	assert.Equal(t, filepath.Join(dir, "acme.state"), acmeConfig.StatePath)

	for _, path := range []string{acmeConfig.CachePath, acmeConfig.StatePath, config.StatePath()} {
		assert.Equal(t, dir, filepath.Dir(path))
	}
}

func TestConfig_SANCertManagerConfigCarriesTheACMEFlags(t *testing.T) {
	config := Config{
		AlternateConfigDir: t.TempDir(),
		ACMEEmail:          "admin@example.com",
		ACMEDNSProvider:    "cloudflare",
		ACMEPreferWildcard: true,
		ACMEHTTPFallback:   true,
	}

	acmeConfig := config.SANCertManagerConfig()

	assert.Equal(t, "admin@example.com", acmeConfig.Email)
	assert.Equal(t, acme.ProviderName("cloudflare"), acmeConfig.DNSProvider)
	assert.True(t, acmeConfig.PreferWildcard)
	assert.True(t, acmeConfig.HTTPFallback)

	// An unset --acme-directory means production, not an empty URL.
	assert.Equal(t, acme.DefaultProductionDirectory, acmeConfig.Directory)
}
