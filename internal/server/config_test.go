package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	assert.Equal(t, filepath.Join(dir, "dash-proxy.state"), config.StatePath())
	assert.Equal(t, filepath.Join(dir, "certs"), config.CertificatePath())
}

// The gem copies the old kamal-proxy-config volume into dash-proxy-config
// verbatim, so a freshly renamed proxy finds a data directory holding
// kamal-proxy.state and no dash-proxy.state. Seeding the current file from it
// is what keeps the routing table across the rename; without it the proxy boots
// empty and every service has to be re-registered by a deploy.
func TestConfig_AdoptLegacyStateSeedsTheCurrentFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kamal-proxy.state"), []byte(`{"services":[]}`), 0o600))

	config := Config{AlternateConfigDir: dir}
	require.NoError(t, config.AdoptLegacyState())

	contents, err := os.ReadFile(config.StatePath())
	require.NoError(t, err)
	assert.JSONEq(t, `{"services":[]}`, string(contents))
}

// Copied, not renamed: an operator who rolls back to a pre-rename image has to
// find the table where that image looks for it.
func TestConfig_AdoptLegacyStateLeavesTheLegacyFileInPlace(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "kamal-proxy.state")
	require.NoError(t, os.WriteFile(legacy, []byte(`{"services":[]}`), 0o600))

	config := Config{AlternateConfigDir: dir}
	require.NoError(t, config.AdoptLegacyState())

	assert.FileExists(t, legacy)
}

// Adoption happens once. A later boot must not clobber a live routing table
// with whatever the stale legacy file still holds.
func TestConfig_AdoptLegacyStateNeverOverwritesTheCurrentFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kamal-proxy.state"), []byte(`{"services":["stale"]}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dash-proxy.state"), []byte(`{"services":[]}`), 0o600))

	config := Config{AlternateConfigDir: dir}
	require.NoError(t, config.AdoptLegacyState())

	contents, err := os.ReadFile(config.StatePath())
	require.NoError(t, err)
	assert.JSONEq(t, `{"services":[]}`, string(contents))
}

// A first boot has neither file and is not an upgrade.
func TestConfig_AdoptLegacyStateIsANoopWithNothingToAdopt(t *testing.T) {
	config := Config{AlternateConfigDir: t.TempDir()}

	require.NoError(t, config.AdoptLegacyState())
	assert.NoFileExists(t, config.StatePath())
}

// StatePath always names the current file, so an upgraded host converges onto
// it instead of writing the legacy name forever — which is what would make the
// fallback impossible to retire in stage 3d.
func TestConfig_StatePathAlwaysNamesTheCurrentFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kamal-proxy.state"), []byte(`{"services":[]}`), 0o600))

	config := Config{AlternateConfigDir: dir}
	assert.Equal(t, filepath.Join(dir, "dash-proxy.state"), config.StatePath())
	assert.Equal(t, filepath.Join(dir, "kamal-proxy.state"), config.LegacyStatePath())
}

func TestConfig_SocketPathHonorsEnvOverride(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "custom.sock")
	t.Setenv("DASH_PROXY_SOCKET", socketPath)

	config := Config{}
	assert.Equal(t, socketPath, config.SocketPath())
}

// The gem sets KAMAL_PROXY_SOCKET on containers it booted before the rename,
// and a running proxy is talked to over whatever socket it opened.
func TestConfig_SocketPathStillHonorsTheLegacyEnvOverride(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "legacy.sock")
	t.Setenv("KAMAL_PROXY_SOCKET", socketPath)

	config := Config{}
	assert.Equal(t, socketPath, config.SocketPath())
}

func TestConfig_SocketPathPrefersTheCurrentEnvOverride(t *testing.T) {
	current := filepath.Join(t.TempDir(), "current.sock")
	t.Setenv("DASH_PROXY_SOCKET", current)
	t.Setenv("KAMAL_PROXY_SOCKET", filepath.Join(t.TempDir(), "legacy.sock"))

	config := Config{}
	assert.Equal(t, current, config.SocketPath())
}

func TestConfig_SocketPathDefaultsToTheCurrentName(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	config := Config{}
	assert.Equal(t, "dash-proxy.sock", filepath.Base(config.SocketPath()))
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
