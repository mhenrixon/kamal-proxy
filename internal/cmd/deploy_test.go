package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server"
)

func TestDeployCommand_TLSRequiresHost(t *testing.T) {
	assertTLSHostValidation := func(t *testing.T, hosts []string, allowed bool) {
		t.Helper()

		cmd := newDeployCommand()
		cmd.args.ServiceOptions.Hosts = hosts
		cmd.args.ServiceOptions.TLSEnabled = true

		err := cmd.preRun(cmd.cmd, []string{"test-service"})

		if allowed {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, "host must be set when using TLS")
			require.ErrorIs(t, err, server.ErrServiceOptionsInvalid)
		}
	}

	assertTLSHostValidation(t, nil, false)
	assertTLSHostValidation(t, []string{""}, false)
	assertTLSHostValidation(t, []string{"*.example.com", ""}, false)

	assertTLSHostValidation(t, []string{"example.com"}, true)
	assertTLSHostValidation(t, []string{"example.com", "*.example.com"}, true)
}

func TestDeployCommand_PathTimeoutParsing(t *testing.T) {
	tests := []struct {
		name                  string
		args                  []string
		expectedError         string
		expectedPathResponses []server.PathTimeout
		expectedPathRequests  []server.PathTimeout
		expectedRequest       time.Duration
	}{
		{
			name:                  "no flags leaves the timeouts unset",
			args:                  []string{"--target=web:3000"},
			expectedPathResponses: nil,
			expectedPathRequests:  nil,
		},
		{
			name: "repeated path timeouts accumulate, longest prefix first",
			args: []string{"--target=web:3000", "--path-timeout=/api=2s", "--path-timeout=api/reports/=5m"},
			expectedPathResponses: []server.PathTimeout{
				{PathPrefix: "/api/reports", Timeout: 5 * time.Minute},
				{PathPrefix: "/api", Timeout: 2 * time.Second},
			},
		},
		{
			name: "a zero timeout disables the timeout for that prefix",
			args: []string{"--target=web:3000", "--path-timeout=/stream=0"},
			expectedPathResponses: []server.PathTimeout{
				{PathPrefix: "/stream", Timeout: 0},
			},
		},
		{
			name:            "request deadline with a per-path override",
			args:            []string{"--target=web:3000", "--request-timeout=60s", "--path-request-timeout=/downloads=0"},
			expectedRequest: time.Minute,
			expectedPathRequests: []server.PathTimeout{
				{PathPrefix: "/downloads", Timeout: 0},
			},
		},
		{
			name:          "an unparseable duration is rejected",
			args:          []string{"--target=web:3000", "--path-timeout=/api=soon"},
			expectedError: "invalid --path-timeout duration for '/api'",
		},
		{
			name:          "a negative duration is rejected",
			args:          []string{"--target=web:3000", "--path-timeout=/api=-5s"},
			expectedError: "invalid --path-timeout duration for '/api'",
		},
		{
			name:          "a negative request deadline is rejected",
			args:          []string{"--target=web:3000", "--path-request-timeout=/api=-5s"},
			expectedError: "invalid --path-request-timeout duration for '/api'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDeployCommand()
			require.NoError(t, cmd.cmd.Flags().Parse(tt.args))

			err := cmd.preRun(cmd.cmd, []string{"test-service"})

			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedPathResponses, cmd.args.TargetOptions.PathResponseTimeouts)
			assert.Equal(t, tt.expectedPathRequests, cmd.args.TargetOptions.PathRequestTimeouts)
			assert.Equal(t, tt.expectedRequest, cmd.args.TargetOptions.RequestTimeout)
		})
	}
}

func TestDeployCommand_TLSOnDemandURL(t *testing.T) {
	t.Run("host is not required when a TLS on-demand URL is set", func(t *testing.T) {
		cmd := newDeployCommand()
		cmd.args.ServiceOptions.TLSEnabled = true
		cmd.args.ServiceOptions.TLSOnDemandURL = "https://example.com/allow-host"

		require.NoError(t, cmd.preRun(cmd.cmd, []string{"test-service"}))
	})

	t.Run("hosts cannot be combined with a TLS on-demand URL", func(t *testing.T) {
		cmd := newDeployCommand()
		cmd.args.ServiceOptions.TLSEnabled = true
		cmd.args.ServiceOptions.TLSOnDemandURL = "https://example.com/allow-host"
		cmd.args.ServiceOptions.Hosts = []string{"example.com"}

		err := cmd.preRun(cmd.cmd, []string{"test-service"})
		require.ErrorContains(t, err, "cannot set hosts when using a TLS on-demand URL")
		require.ErrorIs(t, err, server.ErrServiceOptionsInvalid)
	})

	t.Run("the TLS on-demand URL must be valid", func(t *testing.T) {
		cmd := newDeployCommand()
		cmd.args.ServiceOptions.TLSEnabled = true
		cmd.args.ServiceOptions.TLSOnDemandURL = "ftp://example.com/allow-host"

		err := cmd.preRun(cmd.cmd, []string{"test-service"})
		require.ErrorContains(t, err, "unsupported scheme")
		require.ErrorIs(t, err, server.ErrServiceOptionsInvalid)
	})
}

func TestDeployCommand_CanonicalHostValidation(t *testing.T) {
	tests := []struct {
		name          string
		hosts         []string
		canonicalHost string
		expectError   bool
		expectedError string
	}{
		{
			name:          "valid canonical host in hosts list",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "example.com",
			expectError:   false,
		},
		{
			name:          "valid canonical host in hosts list with www",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "www.example.com",
			expectError:   false,
		},
		{
			name:          "canonical host not in hosts list",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "api.example.com",
			expectError:   true,
			expectedError: "canonical-host 'api.example.com' must be present in the hosts list: [example.com www.example.com]",
		},
		{
			name:          "canonical host empty with hosts",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "",
			expectError:   false,
		},
		{
			name:          "canonical host with no hosts",
			hosts:         []string{},
			canonicalHost: "example.com",
			expectError:   false,
		},
		{
			name:          "both canonical host and hosts empty",
			hosts:         []string{},
			canonicalHost: "",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDeployCommand()

			cmd.args.ServiceOptions.Hosts = tt.hosts
			cmd.args.ServiceOptions.CanonicalHost = tt.canonicalHost
			cmd.args.ServiceOptions.TLSEnabled = false

			mockCmd := &cobra.Command{}

			err := cmd.preRun(mockCmd, []string{"test-service"})

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDeployCommand_TargetTryFlags(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		expectedError    string
		expectedDuration time.Duration
		expectedInterval time.Duration
	}{
		{
			name: "unset leaves retries off",
			args: []string{"--target=web:3000"},
		},
		{
			name:             "try duration alone uses the default interval",
			args:             []string{"--target=web:3000", "--target-try-duration=5s"},
			expectedDuration: 5 * time.Second,
		},
		{
			name:             "try duration with an explicit interval",
			args:             []string{"--target=web:3000", "--target-try-duration=5s", "--target-try-interval=100ms"},
			expectedDuration: 5 * time.Second,
			expectedInterval: 100 * time.Millisecond,
		},
		{
			name:          "an interval without a duration is rejected",
			args:          []string{"--target=web:3000", "--target-try-interval=100ms"},
			expectedError: "target-try-interval requires target-try-duration",
		},
		{
			name:          "a negative duration is rejected",
			args:          []string{"--target=web:3000", "--target-try-duration=-5s"},
			expectedError: "target-try-duration cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDeployCommand()
			require.NoError(t, cmd.cmd.Flags().Parse(tt.args))

			err := cmd.preRun(cmd.cmd, []string{"test-service"})

			if tt.expectedError != "" {
				require.ErrorIs(t, err, server.ErrServiceOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedDuration, cmd.args.ServiceOptions.TargetTryDuration)
			assert.Equal(t, tt.expectedInterval, cmd.args.ServiceOptions.TargetTryInterval)
		})
	}
}

func TestDeployCommand_InterceptErrorsFlag(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		expectedError    string
		expectedStatuses []int
	}{
		{
			name: "unset leaves interception off",
			args: []string{"--target=web:3000"},
		},
		{
			name:             "a comma-separated list",
			args:             []string{"--target=web:3000", "--intercept-errors=502,503,504"},
			expectedStatuses: []int{502, 503, 504},
		},
		{
			name:             "repeated flags accumulate",
			args:             []string{"--target=web:3000", "--intercept-errors=502", "--intercept-errors=503"},
			expectedStatuses: []int{502, 503},
		},
		{
			name:          "a status outside the error range is rejected",
			args:          []string{"--target=web:3000", "--intercept-errors=302"},
			expectedError: "intercept-errors must be a 4xx or 5xx status code, got 302",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDeployCommand()
			require.NoError(t, cmd.cmd.Flags().Parse(tt.args))

			err := cmd.preRun(cmd.cmd, []string{"test-service"})

			if tt.expectedError != "" {
				require.ErrorIs(t, err, server.ErrServiceOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatuses, cmd.args.ServiceOptions.InterceptErrorStatuses)
		})
	}
}

func TestDeployCommand_TargetPoolFlags(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		expectedError string
		expected      server.TargetOptions
	}{
		{
			name:     "unset leaves every pool field at zero, so the server resolves them",
			args:     []string{"--target=web:3000"},
			expected: server.TargetOptions{},
		},
		{
			name: "each flag binds to its own field",
			args: []string{
				"--target=web:3000",
				"--target-max-conns=5",
				"--target-max-idle-conns=3",
				"--target-idle-conn-timeout=45s",
				"--target-dial-timeout=3s",
				"--target-disable-keep-alives",
			},
			expected: server.TargetOptions{
				MaxConnsPerHost:     5,
				MaxIdleConnsPerHost: 3,
				IdleConnTimeout:     45 * time.Second,
				DialTimeout:         3 * time.Second,
				DisableKeepAlives:   true,
			},
		},
		{
			name:          "a negative max conns is rejected",
			args:          []string{"--target=web:3000", "--target-max-conns=-1"},
			expectedError: "target-max-conns cannot be negative",
		},
		{
			name:          "a negative max idle conns is rejected",
			args:          []string{"--target=web:3000", "--target-max-idle-conns=-1"},
			expectedError: "target-max-idle-conns cannot be negative",
		},
		{
			name:          "a negative idle conn timeout is rejected",
			args:          []string{"--target=web:3000", "--target-idle-conn-timeout=-1s"},
			expectedError: "target-idle-conn-timeout cannot be negative",
		},
		{
			name:          "a negative dial timeout is rejected",
			args:          []string{"--target=web:3000", "--target-dial-timeout=-1s"},
			expectedError: "target-dial-timeout cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDeployCommand()
			require.NoError(t, cmd.cmd.Flags().Parse(tt.args))

			err := cmd.preRun(cmd.cmd, []string{"test-service"})

			if tt.expectedError != "" {
				require.ErrorIs(t, err, server.ErrTargetOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected.MaxConnsPerHost, cmd.args.TargetOptions.MaxConnsPerHost)
			assert.Equal(t, tt.expected.MaxIdleConnsPerHost, cmd.args.TargetOptions.MaxIdleConnsPerHost)
			assert.Equal(t, tt.expected.IdleConnTimeout, cmd.args.TargetOptions.IdleConnTimeout)
			assert.Equal(t, tt.expected.DialTimeout, cmd.args.TargetOptions.DialTimeout)
			assert.Equal(t, tt.expected.DisableKeepAlives, cmd.args.TargetOptions.DisableKeepAlives)
		})
	}
}

func TestParseBasicAuthFlag(t *testing.T) {
	tests := []struct {
		name             string
		value            string
		expectedUsername string
		expectedPassword string
		expectError      bool
	}{
		{
			name:             "a simple credential",
			value:            "admin:s3cr3t",
			expectedUsername: "admin",
			expectedPassword: "s3cr3t",
		},
		{
			// Passwords may contain colons; usernames may not. Splitting anywhere
			// but the first colon corrupts the password.
			name:             "splits on the first colon only",
			value:            "admin:pa:ss:word",
			expectedUsername: "admin",
			expectedPassword: "pa:ss:word",
		},
		{name: "no colon", value: "adminpass", expectError: true},
		{name: "empty username", value: ":pass", expectError: true},
		{name: "empty password", value: "admin:", expectError: true},
		{name: "colon only", value: ":", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, password, err := parseBasicAuthFlag(tt.value)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedUsername, username)
			assert.Equal(t, tt.expectedPassword, password)
		})
	}
}

func TestDeployCommand_BasicAuthEncodesCredential(t *testing.T) {
	cmd := newDeployCommand()
	require.NoError(t, cmd.cmd.Flags().Parse([]string{"--target=web:3000", "--basic-auth=admin:s3cr3t"}))
	require.NoError(t, cmd.preRun(cmd.cmd, []string{"test-service"}))

	encoded := cmd.args.ServiceOptions.BasicAuth
	require.NotEmpty(t, encoded)

	// What crosses the RPC socket must be a hash, never the credential.
	assert.NotContains(t, encoded, "admin")
	assert.NotContains(t, encoded, "s3cr3t")
	assert.True(t, strings.HasPrefix(encoded, "sha256:"))

	// And it must be something the server can read back.
	require.NoError(t, server.ServiceOptions{BasicAuth: encoded}.Validate())
}

func TestDeployCommand_BasicAuthRejectsMalformedValues(t *testing.T) {
	cmd := newDeployCommand()
	require.NoError(t, cmd.cmd.Flags().Parse([]string{"--target=web:3000", "--basic-auth=adminpass"}))

	err := cmd.preRun(cmd.cmd, []string{"test-service"})

	require.ErrorIs(t, err, server.ErrServiceOptionsInvalid)
	require.ErrorContains(t, err, "basic-auth")
}

func TestDeployCommand_BasicAuthAbsentLeavesServiceUnprotected(t *testing.T) {
	cmd := newDeployCommand()
	require.NoError(t, cmd.cmd.Flags().Parse([]string{"--target=web:3000"}))

	require.NoError(t, cmd.preRun(cmd.cmd, []string{"test-service"}))
	assert.Empty(t, cmd.args.ServiceOptions.BasicAuth)
}
