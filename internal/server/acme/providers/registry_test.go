package providers

import (
	"testing"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The registry and the detection order are the two halves of one table: a
// provider present in one but not the other silently drops out of either
// auto-detection or explicit selection. These tests make that drift a named
// failure instead.

func TestDetectionOrder_CoversRegistryExactly(t *testing.T) {
	for name := range registry {
		assert.Contains(t, detectionOrder, name,
			"provider %s is in the registry but missing from detectionOrder", name)
	}

	seen := map[acme.ProviderName]bool{}
	for _, name := range detectionOrder {
		_, ok := registry[name]
		assert.True(t, ok, "provider %s is in detectionOrder but missing from the registry", name)
		assert.False(t, seen[name], "provider %s appears twice in detectionOrder", name)
		seen[name] = true
	}

	assert.Len(t, detectionOrder, len(registry))
}

func TestRegistry_EntriesAreComplete(t *testing.T) {
	for name, provider := range registry {
		t.Run(string(name), func(t *testing.T) {
			assert.NotEmpty(t, provider.DisplayName)
			assert.NotEmpty(t, provider.Required)
			assert.NotEmpty(t, provider.Docs)
			assert.NotNil(t, provider.New)
		})
	}
}

// Cloudflare is the one provider whose credential rule is not a flat AND:
// CF_API_TOKEN or CF_DNS_API_TOKEN or (CF_API_KEY + CF_API_EMAIL).
func TestDetectProviderName_CloudflareAlternatives(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"api token", map[string]string{"CF_API_TOKEN": "token"}},
		{"dns api token", map[string]string{"CF_DNS_API_TOKEN": "token"}},
		{"key and email", map[string]string{"CF_API_KEY": "key", "CF_API_EMAIL": "cf@example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			name, found := DetectProviderName()
			assert.True(t, found)
			assert.Equal(t, acme.ProviderCloudflare, name)
		})
	}
}

// A lone CF_API_KEY without its email is not a credential set; detection must
// not stop at Cloudflare for it.
func TestDetectProviderName_CloudflarePartialKeyDoesNotMatch(t *testing.T) {
	t.Setenv("CF_API_KEY", "key")
	t.Setenv("DO_AUTH_TOKEN", "token")

	name, found := DetectProviderName()
	assert.True(t, found)
	assert.Equal(t, acme.ProviderDigitalOcean, name)
}

// The credential error must still name the specific missing variables so the
// operator knows what to set.
func TestNewProvider_ErrorNamesMissingVariables(t *testing.T) {
	tests := []struct {
		provider acme.ProviderName
		expect   []string
	}{
		{acme.ProviderCloudflare, []string{"CF_API_TOKEN", "CF_API_KEY", "CF_API_EMAIL"}},
		{acme.ProviderDigitalOcean, []string{"DO_AUTH_TOKEN"}},
		{acme.ProviderNamecheap, []string{"NAMECHEAP_API_USER", "NAMECHEAP_API_KEY"}},
		{acme.ProviderGoDaddy, []string{"GODADDY_API_KEY", "GODADDY_API_SECRET"}},
		{acme.ProviderHetzner, []string{"HETZNER_API_KEY"}},
		{acme.ProviderVultr, []string{"VULTR_API_KEY"}},
		{acme.ProviderGoogleCloud, []string{"GCE_PROJECT"}},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			_, err := NewProvider(tt.provider)
			require.ErrorIs(t, err, acme.ErrMissingCredentials)
			for _, envVar := range tt.expect {
				assert.Contains(t, err.Error(), envVar)
			}
		})
	}
}

// Route53 keeps its no-boot-check contract: the AWS SDK resolves credentials
// from the environment, shared config, or an IAM role on its own, so an empty
// environment must not produce ErrMissingCredentials.
func TestNewProvider_Route53SkipsCredentialCheck(t *testing.T) {
	provider, ok := registry[acme.ProviderRoute53]
	require.True(t, ok)
	assert.True(t, provider.NoBootCheck)
}
