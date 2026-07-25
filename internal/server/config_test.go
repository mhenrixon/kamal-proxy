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
