package cmd

import (
	"os"
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

func TestRunCommand_ProxyProtocolFlags(t *testing.T) {
	globalConfig = server.Config{}

	cmd := newRunCommand().cmd

	flag := cmd.Flags().Lookup("proxy-protocol")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)

	require.NoError(t, cmd.Flags().Parse([]string{
		"--proxy-protocol",
		"--proxy-protocol-allow-ip=10.0.0.0/8,203.0.113.7",
	}))

	assert.True(t, globalConfig.ProxyProtocol)
	assert.Equal(t, []string{"10.0.0.0/8", "203.0.113.7"}, globalConfig.ProxyProtocolAllowIPs)
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

func TestRunCommand_MinTLSFlag(t *testing.T) {
	// This feature teaches operators to export MIN_TLS, so a developer running the
	// suite is unusually likely to have it set. The prefixed key wins in findEnv,
	// so pinning it here makes the default deterministic. Setting MIN_TLS to ""
	// would not work: findEnv reports an empty value as present.
	t.Setenv("KAMAL_PROXY_MIN_TLS", server.DefaultMinTLSVersion)

	globalConfig = server.Config{}

	cmd := newRunCommand().cmd

	flag := cmd.Flags().Lookup("min-tls")
	require.NotNil(t, flag)
	assert.Equal(t, server.DefaultMinTLSVersion, flag.DefValue)

	require.NoError(t, cmd.Flags().Parse([]string{"--min-tls=1.3"}))
	assert.Equal(t, "1.3", globalConfig.MinTLS)
}

func TestRunCommand_MinTLSPreRun(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expectedError string
	}{
		// The accepted spellings have to be exercised through the command, not
		// just through ParseMinTLSVersion: preRun is what an operator's value
		// actually passes through, and the README promises upstream's tls1_2
		// grammar keeps working here.
		{name: "default", value: server.DefaultMinTLSVersion},
		{name: "1.3", value: "1.3"},
		{name: "upstream tls1_2 grammar", value: "tls1_2"},
		{name: "upstream tls1_3 grammar", value: "tls1_3"},
		{name: "TLSv prefix", value: "TLSv1.3"},

		{name: "TLS 1.0", value: "1.0", expectedError: "cannot be enabled"},
		{name: "TLS 1.1", value: "1.1", expectedError: "cannot be enabled"},
		{name: "upstream tls1_0 grammar", value: "tls1_0", expectedError: "cannot be enabled"},
		{name: "not a version", value: "banana", expectedError: "is not a TLS version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// preRun validates the log format and trace mode too, so an ambient
			// LOG_FORMAT or TRACE_CONTEXT would fail this test for a reason that
			// has nothing to do with min-tls.
			testClearEnv(t, "LOG_FORMAT", "TRACE_CONTEXT")

			globalConfig = server.Config{}

			runCommand := newRunCommand()
			require.NoError(t, runCommand.cmd.Flags().Parse([]string{"--min-tls=" + tt.value}))

			err := runCommand.preRun(runCommand.cmd, nil)

			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				require.ErrorContains(t, err, "min-tls")
				return
			}

			require.NoError(t, err)
			// The server parses this same string again at bind time, so what
			// preRun accepted has to be what reaches the listener.
			assert.Equal(t, tt.value, globalConfig.MinTLS)
		})
	}
}

// testClearEnv unsets a variable for the duration of the test. Pinning it to
// the expected default instead would make a default assertion tautological:
// findEnv prefers whatever is set, so the fallback registered in run.go would
// never be the value under test. t.Setenv is called only to register the
// restore - findEnv reports an empty value as present, so the unset is what
// actually clears it.
func testClearEnv(t *testing.T, keys ...string) {
	t.Helper()

	for _, key := range keys {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))

		t.Setenv(ENV_PREFIX+key, "")
		require.NoError(t, os.Unsetenv(ENV_PREFIX+key))
	}
}

func TestRunCommand_LogFormatFlag(t *testing.T) {
	testClearEnv(t, "LOG_FORMAT")

	globalConfig = server.Config{}

	cmd := newRunCommand().cmd

	flag := cmd.Flags().Lookup("log-format")
	require.NotNil(t, flag)
	assert.Equal(t, server.DefaultLogFormat, flag.DefValue)

	require.NoError(t, cmd.Flags().Parse([]string{"--log-format=text"}))
	assert.Equal(t, "text", globalConfig.LogFormat)
}

func TestRunCommand_TraceContextFlag(t *testing.T) {
	testClearEnv(t, "TRACE_CONTEXT")

	globalConfig = server.Config{}

	cmd := newRunCommand().cmd

	flag := cmd.Flags().Lookup("trace-context")
	require.NotNil(t, flag)
	assert.Equal(t, server.DefaultTraceContextMode, flag.DefValue)

	require.NoError(t, cmd.Flags().Parse([]string{"--trace-context=generate"}))
	assert.Equal(t, "generate", globalConfig.TraceContext)
}

func TestRunCommand_ObservabilityPreRun(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{name: "defaults", args: nil},
		{name: "text logs", args: []string{"--log-format=text"}},
		{name: "generate traces", args: []string{"--trace-context=generate"}},

		{name: "bad log format", args: []string{"--log-format=xml"}, expectedError: "log-format"},
		{name: "bad trace mode", args: []string{"--trace-context=yes"}, expectedError: "trace-context"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testClearEnv(t, "LOG_FORMAT", "TRACE_CONTEXT", "MIN_TLS")

			globalConfig = server.Config{}

			runCommand := newRunCommand()
			require.NoError(t, runCommand.cmd.Flags().Parse(tt.args))

			err := runCommand.preRun(runCommand.cmd, nil)

			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
		})
	}
}
