package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server"
)

func TestRunCommand_IgnoreRestoreErrorsFlag(t *testing.T) {
	cmd := newRunCommand().cmd

	flag := cmd.Flags().Lookup("ignore-restore-errors")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestRunCommand_RecheckTargetsOnRestoreFlag(t *testing.T) {
	cmd := newRunCommand().cmd

	flag := cmd.Flags().Lookup("recheck-targets-on-restore")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestRunCommand_ReusePortFlag(t *testing.T) {
	cmd := newRunCommand().cmd

	flag := cmd.Flags().Lookup("reuse-port")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestRunCommand_DataDirFlag(t *testing.T) {
	globalConfig = server.Config{}

	cmd := newRunCommand().cmd
	require.NoError(t, cmd.Flags().Parse([]string{"--data-dir=/var/lib/kamal-proxy"}))

	assert.Equal(t, "/var/lib/kamal-proxy", globalConfig.AlternateConfigDir)
}

func TestRunCommand_TimeoutFlagDefaults(t *testing.T) {
	tests := []struct {
		flag     string
		expected time.Duration
	}{
		{"read-header-timeout", server.DefaultReadHeaderTimeout},
		{"read-timeout", server.DefaultReadTimeout},
		{"write-timeout", server.DefaultWriteTimeout},
		{"idle-timeout", server.DefaultIdleTimeout},
		{"shutdown-timeout", server.DefaultShutdownTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			cmd := newRunCommand().cmd

			flag := cmd.Flags().Lookup(tt.flag)
			require.NotNil(t, flag, "flag --%s is not registered", tt.flag)
			assert.Equal(t, tt.expected.String(), flag.DefValue)
		})
	}
}

func TestRunCommand_TimeoutFlagsPopulateConfig(t *testing.T) {
	globalConfig = server.Config{}

	cmd := newRunCommand().cmd
	require.NoError(t, cmd.Flags().Parse([]string{
		"--read-header-timeout=11s",
		"--read-timeout=22s",
		"--write-timeout=33s",
		"--idle-timeout=44s",
	}))

	assert.Equal(t, 11*time.Second, globalConfig.ReadHeaderTimeout)
	assert.Equal(t, 22*time.Second, globalConfig.ReadTimeout)
	assert.Equal(t, 33*time.Second, globalConfig.WriteTimeout)
	assert.Equal(t, 44*time.Second, globalConfig.IdleTimeout)
}

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		key      string
		fallback time.Duration
		expected time.Duration
	}{
		{
			name:     "unset falls back",
			key:      "READ_HEADER_TIMEOUT",
			fallback: 30 * time.Second,
			expected: 30 * time.Second,
		},
		{
			name:     "prefixed value wins",
			env:      map[string]string{"KAMAL_PROXY_READ_HEADER_TIMEOUT": "5s"},
			key:      "READ_HEADER_TIMEOUT",
			fallback: 30 * time.Second,
			expected: 5 * time.Second,
		},
		{
			name:     "unprefixed value is accepted",
			env:      map[string]string{"READ_HEADER_TIMEOUT": "90s"},
			key:      "READ_HEADER_TIMEOUT",
			fallback: 30 * time.Second,
			expected: 90 * time.Second,
		},
		{
			name:     "unparseable value falls back",
			env:      map[string]string{"KAMAL_PROXY_READ_HEADER_TIMEOUT": "not-a-duration"},
			key:      "READ_HEADER_TIMEOUT",
			fallback: 30 * time.Second,
			expected: 30 * time.Second,
		},
		{
			name:     "zero disables the timeout",
			env:      map[string]string{"KAMAL_PROXY_WRITE_TIMEOUT": "0"},
			key:      "WRITE_TIMEOUT",
			fallback: 30 * time.Second,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			assert.Equal(t, tt.expected, getEnvDuration(tt.key, tt.fallback))
		})
	}
}
