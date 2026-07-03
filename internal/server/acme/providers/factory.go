package providers

import (
	"fmt"
	"os"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/namecheap"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/providers/dns/vultr"
)

// ProviderInfo contains metadata about a DNS provider
type ProviderInfo struct {
	Name            acme.ProviderName
	DisplayName     string
	RequiredEnvVars []string
	OptionalEnvVars []string
	Documentation   string
}

// GetProviderInfo returns information about all supported providers
func GetProviderInfo() map[acme.ProviderName]ProviderInfo {
	return map[acme.ProviderName]ProviderInfo{
		acme.ProviderCloudflare: {
			Name:            acme.ProviderCloudflare,
			DisplayName:     "Cloudflare",
			RequiredEnvVars: []string{"CF_API_TOKEN"},
			OptionalEnvVars: []string{"CF_API_EMAIL", "CF_API_KEY", "CF_DNS_API_TOKEN", "CF_ZONE_API_TOKEN"},
			Documentation:   "https://go-acme.github.io/lego/dns/cloudflare/",
		},
		acme.ProviderRoute53: {
			Name:            acme.ProviderRoute53,
			DisplayName:     "AWS Route53",
			RequiredEnvVars: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
			OptionalEnvVars: []string{"AWS_REGION", "AWS_HOSTED_ZONE_ID", "AWS_PROFILE"},
			Documentation:   "https://go-acme.github.io/lego/dns/route53/",
		},
		acme.ProviderDigitalOcean: {
			Name:            acme.ProviderDigitalOcean,
			DisplayName:     "DigitalOcean",
			RequiredEnvVars: []string{"DO_AUTH_TOKEN"},
			OptionalEnvVars: []string{},
			Documentation:   "https://go-acme.github.io/lego/dns/digitalocean/",
		},
		acme.ProviderGoogleCloud: {
			Name:            acme.ProviderGoogleCloud,
			DisplayName:     "Google Cloud DNS",
			RequiredEnvVars: []string{"GCE_PROJECT"},
			OptionalEnvVars: []string{"GCE_SERVICE_ACCOUNT_FILE", "GOOGLE_APPLICATION_CREDENTIALS"},
			Documentation:   "https://go-acme.github.io/lego/dns/gcloud/",
		},
		acme.ProviderNamecheap: {
			Name:            acme.ProviderNamecheap,
			DisplayName:     "Namecheap",
			RequiredEnvVars: []string{"NAMECHEAP_API_USER", "NAMECHEAP_API_KEY"},
			OptionalEnvVars: []string{"NAMECHEAP_SANDBOX"},
			Documentation:   "https://go-acme.github.io/lego/dns/namecheap/",
		},
		acme.ProviderGoDaddy: {
			Name:            acme.ProviderGoDaddy,
			DisplayName:     "GoDaddy",
			RequiredEnvVars: []string{"GODADDY_API_KEY", "GODADDY_API_SECRET"},
			OptionalEnvVars: []string{},
			Documentation:   "https://go-acme.github.io/lego/dns/godaddy/",
		},
		acme.ProviderHetzner: {
			Name:            acme.ProviderHetzner,
			DisplayName:     "Hetzner",
			RequiredEnvVars: []string{"HETZNER_API_KEY"},
			OptionalEnvVars: []string{},
			Documentation:   "https://go-acme.github.io/lego/dns/hetzner/",
		},
		acme.ProviderVultr: {
			Name:            acme.ProviderVultr,
			DisplayName:     "Vultr",
			RequiredEnvVars: []string{"VULTR_API_KEY"},
			OptionalEnvVars: []string{},
			Documentation:   "https://go-acme.github.io/lego/dns/vultr/",
		},
	}
}

// NewProvider creates a DNS provider based on the provider name
func NewProvider(name acme.ProviderName) (challenge.Provider, error) {
	switch name {
	case acme.ProviderCloudflare:
		return newCloudflareProvider()
	case acme.ProviderRoute53:
		return newRoute53Provider()
	case acme.ProviderDigitalOcean:
		return newDigitalOceanProvider()
	case acme.ProviderGoogleCloud:
		return newGoogleCloudProvider()
	case acme.ProviderNamecheap:
		return newNamecheapProvider()
	case acme.ProviderGoDaddy:
		return newGoDaddyProvider()
	case acme.ProviderHetzner:
		return newHetznerProvider()
	case acme.ProviderVultr:
		return newVultrProvider()
	case acme.ProviderAuto:
		return autoDetectProvider()
	default:
		return nil, fmt.Errorf("%w: %s", acme.ErrProviderNotSupported, name)
	}
}

// newCloudflareProvider creates a Cloudflare DNS provider
func newCloudflareProvider() (challenge.Provider, error) {
	// Check for API token first (preferred)
	if os.Getenv("CF_API_TOKEN") != "" || os.Getenv("CF_DNS_API_TOKEN") != "" {
		return cloudflare.NewDNSProvider()
	}

	// Fall back to API key + email
	if os.Getenv("CF_API_KEY") != "" && os.Getenv("CF_API_EMAIL") != "" {
		return cloudflare.NewDNSProvider()
	}

	return nil, fmt.Errorf("%w: need CF_API_TOKEN or (CF_API_KEY + CF_API_EMAIL)", acme.ErrMissingCredentials)
}

// newRoute53Provider creates an AWS Route53 DNS provider
func newRoute53Provider() (challenge.Provider, error) {
	// AWS SDK will use credentials from environment, shared credentials file, or IAM role
	return route53.NewDNSProvider()
}

// newDigitalOceanProvider creates a DigitalOcean DNS provider
func newDigitalOceanProvider() (challenge.Provider, error) {
	if os.Getenv("DO_AUTH_TOKEN") == "" {
		return nil, fmt.Errorf("%w: need DO_AUTH_TOKEN", acme.ErrMissingCredentials)
	}
	return digitalocean.NewDNSProvider()
}

// newGoogleCloudProvider creates a Google Cloud DNS provider
func newGoogleCloudProvider() (challenge.Provider, error) {
	if os.Getenv("GCE_PROJECT") == "" {
		return nil, fmt.Errorf("%w: need GCE_PROJECT", acme.ErrMissingCredentials)
	}
	return gcloud.NewDNSProvider()
}

// newNamecheapProvider creates a Namecheap DNS provider
func newNamecheapProvider() (challenge.Provider, error) {
	if os.Getenv("NAMECHEAP_API_USER") == "" || os.Getenv("NAMECHEAP_API_KEY") == "" {
		return nil, fmt.Errorf("%w: need NAMECHEAP_API_USER and NAMECHEAP_API_KEY", acme.ErrMissingCredentials)
	}
	return namecheap.NewDNSProvider()
}

// newGoDaddyProvider creates a GoDaddy DNS provider
func newGoDaddyProvider() (challenge.Provider, error) {
	if os.Getenv("GODADDY_API_KEY") == "" || os.Getenv("GODADDY_API_SECRET") == "" {
		return nil, fmt.Errorf("%w: need GODADDY_API_KEY and GODADDY_API_SECRET", acme.ErrMissingCredentials)
	}
	return godaddy.NewDNSProvider()
}

// newHetznerProvider creates a Hetzner DNS provider
func newHetznerProvider() (challenge.Provider, error) {
	if os.Getenv("HETZNER_API_KEY") == "" {
		return nil, fmt.Errorf("%w: need HETZNER_API_KEY", acme.ErrMissingCredentials)
	}
	return hetzner.NewDNSProvider()
}

// newVultrProvider creates a Vultr DNS provider
func newVultrProvider() (challenge.Provider, error) {
	if os.Getenv("VULTR_API_KEY") == "" {
		return nil, fmt.Errorf("%w: need VULTR_API_KEY", acme.ErrMissingCredentials)
	}
	return vultr.NewDNSProvider()
}

// autoDetectProvider attempts to auto-detect the DNS provider from environment variables
func autoDetectProvider() (challenge.Provider, error) {
	// Try each provider in order of popularity
	providerOrder := []acme.ProviderName{
		acme.ProviderCloudflare,
		acme.ProviderRoute53,
		acme.ProviderDigitalOcean,
		acme.ProviderHetzner,
		acme.ProviderVultr,
		acme.ProviderGoogleCloud,
		acme.ProviderNamecheap,
		acme.ProviderGoDaddy,
	}

	for _, name := range providerOrder {
		provider, err := NewProvider(name)
		if err == nil {
			return provider, nil
		}
	}

	return nil, fmt.Errorf("%w: could not auto-detect DNS provider from environment", acme.ErrProviderNotConfigured)
}

// DetectProviderName detects which provider is configured from environment variables
func DetectProviderName() (acme.ProviderName, bool) {
	// Check in order of popularity
	checks := []struct {
		name     acme.ProviderName
		envCheck func() bool
	}{
		{acme.ProviderCloudflare, func() bool {
			return os.Getenv("CF_API_TOKEN") != "" ||
				os.Getenv("CF_DNS_API_TOKEN") != "" ||
				(os.Getenv("CF_API_KEY") != "" && os.Getenv("CF_API_EMAIL") != "")
		}},
		{acme.ProviderRoute53, func() bool {
			return os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_PROFILE") != ""
		}},
		{acme.ProviderDigitalOcean, func() bool {
			return os.Getenv("DO_AUTH_TOKEN") != ""
		}},
		{acme.ProviderHetzner, func() bool {
			return os.Getenv("HETZNER_API_KEY") != ""
		}},
		{acme.ProviderVultr, func() bool {
			return os.Getenv("VULTR_API_KEY") != ""
		}},
		{acme.ProviderGoogleCloud, func() bool {
			return os.Getenv("GCE_PROJECT") != ""
		}},
		{acme.ProviderNamecheap, func() bool {
			return os.Getenv("NAMECHEAP_API_USER") != "" && os.Getenv("NAMECHEAP_API_KEY") != ""
		}},
		{acme.ProviderGoDaddy, func() bool {
			return os.Getenv("GODADDY_API_KEY") != "" && os.Getenv("GODADDY_API_SECRET") != ""
		}},
	}

	for _, check := range checks {
		if check.envCheck() {
			return check.name, true
		}
	}

	return "", false
}
