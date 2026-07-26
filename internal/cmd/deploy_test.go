package cmd

import (
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
