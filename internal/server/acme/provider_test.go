package acme

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProviderName(t *testing.T) {
	tests := []struct {
		input    string
		expected ProviderName
		wantErr  bool
	}{
		// Cloudflare variations
		{"cloudflare", ProviderCloudflare, false},
		{"Cloudflare", ProviderCloudflare, false},
		{"CLOUDFLARE", ProviderCloudflare, false},
		{"cf", ProviderCloudflare, false},

		// Route53 variations
		{"route53", ProviderRoute53, false},
		{"Route53", ProviderRoute53, false},
		{"aws", ProviderRoute53, false},
		{"r53", ProviderRoute53, false},

		// DigitalOcean variations
		{"digitalocean", ProviderDigitalOcean, false},
		{"DigitalOcean", ProviderDigitalOcean, false},
		{"do", ProviderDigitalOcean, false},

		// Google Cloud variations
		{"gcloud", ProviderGoogleCloud, false},
		{"google", ProviderGoogleCloud, false},
		{"gcp", ProviderGoogleCloud, false},
		{"googledns", ProviderGoogleCloud, false},

		// Namecheap variations
		{"namecheap", ProviderNamecheap, false},
		{"nc", ProviderNamecheap, false},

		// GoDaddy variations
		{"godaddy", ProviderGoDaddy, false},
		{"gd", ProviderGoDaddy, false},

		// Hetzner variations
		{"hetzner", ProviderHetzner, false},
		{"hz", ProviderHetzner, false},

		// Vultr variations
		{"vultr", ProviderVultr, false},
		{"vr", ProviderVultr, false},

		// Auto
		{"auto", ProviderAuto, false},
		{"", ProviderAuto, false},

		// Invalid
		{"invalid", "", true},
		{"notaprovider", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseProviderName(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrProviderNotSupported)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetSupportedProviders(t *testing.T) {
	providers := GetSupportedProviders()

	// Should have all expected providers
	assert.Contains(t, providers, ProviderCloudflare)
	assert.Contains(t, providers, ProviderRoute53)
	assert.Contains(t, providers, ProviderDigitalOcean)
	assert.Contains(t, providers, ProviderGoogleCloud)
	assert.Contains(t, providers, ProviderNamecheap)
	assert.Contains(t, providers, ProviderGoDaddy)
	assert.Contains(t, providers, ProviderHetzner)
	assert.Contains(t, providers, ProviderVultr)
	assert.Contains(t, providers, ProviderAuto)

	assert.Len(t, providers, 9)
}

func TestCheckEnvVars(t *testing.T) {
	tests := []struct {
		name    string
		vars    []string
		setup   func()
		cleanup func()
		wantErr bool
	}{
		{
			name:    "all vars present",
			vars:    []string{"TEST_VAR_1", "TEST_VAR_2"},
			setup:   func() { t.Setenv("TEST_VAR_1", "val1"); t.Setenv("TEST_VAR_2", "val2") },
			cleanup: func() {},
			wantErr: false,
		},
		{
			name:    "missing one var",
			vars:    []string{"TEST_VAR_PRESENT", "TEST_VAR_MISSING"},
			setup:   func() { t.Setenv("TEST_VAR_PRESENT", "val") },
			cleanup: func() {},
			wantErr: true,
		},
		{
			name:    "all vars missing",
			vars:    []string{"TOTALLY_MISSING_1", "TOTALLY_MISSING_2"},
			setup:   func() {},
			cleanup: func() {},
			wantErr: true,
		},
		{
			name:    "empty vars list",
			vars:    []string{},
			setup:   func() {},
			cleanup: func() {},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			defer tt.cleanup()

			err := CheckEnvVars(tt.vars)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrMissingCredentials)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestACMEConfig_Defaults(t *testing.T) {
	config := ACMEConfig{
		Email: "test@example.com",
	}

	// Directory should be empty, will be set to default by NewACMEClient
	assert.Empty(t, config.Directory)
	assert.False(t, config.PreferWildcard)
}

func TestDefaultDirectories(t *testing.T) {
	assert.Equal(t, "https://acme-v02.api.letsencrypt.org/directory", DefaultProductionDirectory)
	assert.Equal(t, "https://acme-staging-v02.api.letsencrypt.org/directory", DefaultStagingDirectory)
}
