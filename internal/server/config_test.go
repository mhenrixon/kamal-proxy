package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
