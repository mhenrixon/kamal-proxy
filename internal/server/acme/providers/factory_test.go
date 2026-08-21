package providers

import (
	"strings"
	"testing"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetProviderInfo(t *testing.T) {
	info := GetProviderInfo()

	// Check all expected providers are present
	providers := []acme.ProviderName{
		acme.ProviderCloudflare,
		acme.ProviderRoute53,
		acme.ProviderDigitalOcean,
		acme.ProviderGoogleCloud,
		acme.ProviderNamecheap,
		acme.ProviderGoDaddy,
		acme.ProviderHetzner,
		acme.ProviderVultr,
	}

	for _, p := range providers {
		t.Run(string(p), func(t *testing.T) {
			providerInfo, ok := info[p]
			require.True(t, ok, "Provider %s should be in info map", p)
			assert.Equal(t, p, providerInfo.Name)
			assert.NotEmpty(t, providerInfo.DisplayName)
			assert.NotEmpty(t, providerInfo.RequiredEnvVars)
			assert.NotEmpty(t, providerInfo.Documentation)
		})
	}
}

func TestGetProviderInfo_Cloudflare(t *testing.T) {
	info := GetProviderInfo()
	cf := info[acme.ProviderCloudflare]

	assert.Equal(t, "Cloudflare", cf.DisplayName)
	assert.Contains(t, cf.RequiredEnvVars, "CF_DNS_API_TOKEN")
	assert.Contains(t, cf.Documentation, "cloudflare")
}

func TestGetProviderInfo_Route53(t *testing.T) {
	info := GetProviderInfo()
	r53 := info[acme.ProviderRoute53]

	assert.Equal(t, "AWS Route53", r53.DisplayName)
	assert.Contains(t, r53.RequiredEnvVars, "AWS_ACCESS_KEY_ID")
	assert.Contains(t, r53.RequiredEnvVars, "AWS_SECRET_ACCESS_KEY")
}

func TestGetProviderInfo_DigitalOcean(t *testing.T) {
	info := GetProviderInfo()
	do := info[acme.ProviderDigitalOcean]

	assert.Equal(t, "DigitalOcean", do.DisplayName)
	assert.Contains(t, do.RequiredEnvVars, "DO_AUTH_TOKEN")
}

func TestNewProvider_InvalidProvider(t *testing.T) {
	_, err := NewProvider("invalid-provider")
	require.Error(t, err)
	assert.ErrorIs(t, err, acme.ErrProviderNotSupported)
}

func TestNewProvider_MissingCredentials(t *testing.T) {
	// These should fail because env vars aren't set
	tests := []acme.ProviderName{
		acme.ProviderCloudflare,
		acme.ProviderDigitalOcean,
		acme.ProviderGoogleCloud,
		acme.ProviderNamecheap,
		acme.ProviderGoDaddy,
		acme.ProviderHetzner,
		acme.ProviderVultr,
	}

	for _, provider := range tests {
		t.Run(string(provider), func(t *testing.T) {
			_, err := NewProvider(provider)
			require.Error(t, err)
			// Should be a missing credentials error
			assert.ErrorIs(t, err, acme.ErrMissingCredentials)
		})
	}
}

// Every credential set the registry advertises for cloudflare must satisfy
// lego's constructor: a set that passes the boot check but cannot construct
// vouches for a broken configuration at exactly the moment the check exists
// to catch it (#115). Cloudflare's constructor is offline, so constructing
// with fake values is safe.
func TestNewProvider_CloudflareCredentialSetsConstruct(t *testing.T) {
	for _, set := range registry[acme.ProviderCloudflare].credentialSets() {
		t.Run(strings.Join(set, "+"), func(t *testing.T) {
			for _, envVar := range set {
				t.Setenv(envVar, "test-value")
			}

			provider, err := NewProvider(acme.ProviderCloudflare)
			require.NoError(t, err)
			assert.NotNil(t, provider)
		})
	}
}

// lego resolves each cloudflare field independently, so a mixed-namespace
// pair like CF_API_KEY + CLOUDFLARE_EMAIL would construct — but the registry
// deliberately fails closed on it: the advertised sets stay canonical (one
// namespace per set, matching the generated README table), and the boot error
// names exactly what to set. This pins that divergence as a decision, not an
// accident — the dangerous direction, passing the check while construction
// fails, is what TestNewProvider_CloudflareCredentialSetsConstruct guards.
func TestNewProvider_CloudflareMixedNamespaceFailsClosed(t *testing.T) {
	t.Setenv("CF_API_KEY", "key")
	t.Setenv("CLOUDFLARE_EMAIL", "cf@example.com")

	_, err := NewProvider(acme.ProviderCloudflare)
	require.ErrorIs(t, err, acme.ErrMissingCredentials)
}

// NewAutoProvider must report the provider the arming walk actually chose —
// not what the looser detection sets would guess — so boot logging can name
// the issuing provider truthfully.
func TestNewAutoProvider_ReportsTheArmedProvider(t *testing.T) {
	// CF_DNS_API_TOKEN satisfies the registry's credential rule AND lego's
	// constructor, so cloudflare — first in detectionOrder — actually arms.
	t.Setenv("CF_DNS_API_TOKEN", "test-token")

	provider, name, err := NewAutoProvider()
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, acme.ProviderCloudflare, name)
}

func TestDetectProviderName_NoCredentials(t *testing.T) {
	// With no env vars set, should return empty
	name, found := DetectProviderName()

	// If no credentials are set in the environment, should not find anything
	// Note: This test might pass or fail depending on the test environment
	// In a clean environment, it should not find any provider
	if !found {
		assert.Empty(t, name)
	}
}

func TestDetectProviderName_CloudflareToken(t *testing.T) {
	t.Setenv("CF_DNS_API_TOKEN", "test-token")

	name, found := DetectProviderName()

	assert.True(t, found)
	assert.Equal(t, acme.ProviderCloudflare, name)
}

func TestDetectProviderName_CloudflareKeyAndEmail(t *testing.T) {
	t.Setenv("CF_API_KEY", "test-key")
	t.Setenv("CF_API_EMAIL", "test@example.com")

	name, found := DetectProviderName()

	assert.True(t, found)
	assert.Equal(t, acme.ProviderCloudflare, name)
}

func TestDetectProviderName_DigitalOcean(t *testing.T) {
	t.Setenv("DO_AUTH_TOKEN", "test-token")

	name, found := DetectProviderName()

	assert.True(t, found)
	assert.Equal(t, acme.ProviderDigitalOcean, name)
}

func TestDetectProviderName_Hetzner(t *testing.T) {
	t.Setenv("HETZNER_API_KEY", "test-key")

	name, found := DetectProviderName()

	assert.True(t, found)
	assert.Equal(t, acme.ProviderHetzner, name)
}

func TestDetectProviderName_Vultr(t *testing.T) {
	t.Setenv("VULTR_API_KEY", "test-key")

	name, found := DetectProviderName()

	assert.True(t, found)
	assert.Equal(t, acme.ProviderVultr, name)
}

func TestDetectProviderName_Priority(t *testing.T) {
	// Set multiple provider credentials - Cloudflare should win (first in order)
	t.Setenv("CF_DNS_API_TOKEN", "cf-token")
	t.Setenv("DO_AUTH_TOKEN", "do-token")

	name, found := DetectProviderName()

	assert.True(t, found)
	assert.Equal(t, acme.ProviderCloudflare, name)
}
