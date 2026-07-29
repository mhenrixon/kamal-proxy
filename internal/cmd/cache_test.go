package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server"
)

func TestDeployCommand_CacheFlags(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		expectedError string
		assertOptions func(t *testing.T, options server.CacheOptions)
	}{
		{
			name: "off by default",
			args: []string{"service1", "--target", "host:1234"},
			assertOptions: func(t *testing.T, options server.CacheOptions) {
				assert.Equal(t, server.CacheOptions{}, options)
			},
		},
		{
			name: "enabled",
			args: []string{"service1", "--target", "host:1234", "--cache"},
			assertOptions: func(t *testing.T, options server.CacheOptions) {
				assert.True(t, options.Enabled)
			},
		},
		{
			name: "every knob",
			args: []string{
				"service1", "--target", "host:1234", "--cache",
				"--cache-max-body", "4096",
				"--cache-max-ttl", "5m",
				"--cache-vary-header", "Accept-Language",
				"--cache-vary-cookie", "locale",
				"--cache-allow-set-cookie",
			},
			assertOptions: func(t *testing.T, options server.CacheOptions) {
				assert.True(t, options.Enabled)
				assert.Equal(t, int64(4096), options.MaxBodySize)
				assert.Equal(t, 5*time.Minute, options.MaxTTL)
				assert.Equal(t, []string{"accept-language"}, options.VaryHeaders)
				assert.Equal(t, []string{"locale"}, options.VaryCookies)
				assert.True(t, options.AllowSetCookie)
			},
		},
		{
			name:          "max body without cache",
			args:          []string{"service1", "--target", "host:1234", "--cache-max-body", "4096"},
			expectedError: "cache-max-body requires cache",
		},
		{
			name:          "max ttl without cache",
			args:          []string{"service1", "--target", "host:1234", "--cache-max-ttl", "5m"},
			expectedError: "cache-max-ttl requires cache",
		},
		{
			name:          "vary header without cache",
			args:          []string{"service1", "--target", "host:1234", "--cache-vary-header", "Accept-Language"},
			expectedError: "cache-vary-header requires cache",
		},
		{
			name:          "allow set cookie without cache",
			args:          []string{"service1", "--target", "host:1234", "--cache-allow-set-cookie"},
			expectedError: "cache-allow-set-cookie requires cache",
		},
		{
			name:          "negative max ttl",
			args:          []string{"service1", "--target", "host:1234", "--cache", "--cache-max-ttl", "-1s"},
			expectedError: "cache-max-ttl cannot be negative",
		},
		{
			name:          "invalid vary header name",
			args:          []string{"service1", "--target", "host:1234", "--cache", "--cache-vary-header", "Accept Language"},
			expectedError: "cache-vary-header must be a header name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deploy := newDeployCommand()
			deploy.cmd.SetArgs(tt.args)

			err := deploy.cmd.ValidateArgs(tt.args[:1])
			require.NoError(t, err)
			require.NoError(t, deploy.cmd.ParseFlags(tt.args[1:]))

			err = deploy.preRun(deploy.cmd, tt.args[:1])

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)

			options := deploy.args.ServiceOptions.Cache
			options.Normalize()
			tt.assertOptions(t, options)
		})
	}
}

func TestRunCommand_CacheStoreValidation(t *testing.T) {
	tests := []struct {
		name          string
		store         string
		expectedError string
	}{
		{name: "default", store: ""},
		{name: "memory", store: server.CacheStoreMemory},
		{name: "redis", store: "redis://localhost:6379/0"},
		{name: "redis over tls", store: "rediss://localhost:6379"},
		{name: "unsupported scheme", store: "memcache://localhost:11211", expectedError: "cache-store must be"},
		{name: "bare host and port", store: "localhost:6379", expectedError: "cache-store must be"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previous := globalConfig
			t.Cleanup(func() { globalConfig = previous })

			run := newRunCommand()
			require.NoError(t, run.cmd.ParseFlags([]string{"--cache-store", tt.store}))

			err := run.preRun(run.cmd, nil)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestCachePurgeCommand_PathPrefixValidation(t *testing.T) {
	tests := []struct {
		name          string
		prefix        string
		expectedError string
	}{
		{name: "empty purges everything", prefix: ""},
		{name: "absolute path", prefix: "/assets"},
		{name: "relative path", prefix: "assets", expectedError: "path-prefix must start with '/'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purge := newCachePurgeCommand()
			if tt.prefix != "" {
				require.NoError(t, purge.cmd.ParseFlags([]string{"--path-prefix", tt.prefix}))
			}

			err := purge.preRun(purge.cmd, []string{"service1"})

			if tt.expectedError == "" {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}
