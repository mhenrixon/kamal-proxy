package acme

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrProviderNotConfigured = errors.New("DNS provider not configured")
	ErrProviderNotSupported  = errors.New("DNS provider not supported")
	ErrMissingCredentials    = errors.New("missing required credentials for DNS provider")
)

// ProviderName represents a supported DNS provider
type ProviderName string

const (
	ProviderCloudflare   ProviderName = "cloudflare"
	ProviderRoute53      ProviderName = "route53"
	ProviderDigitalOcean ProviderName = "digitalocean"
	ProviderGoogleCloud  ProviderName = "gcloud"
	ProviderNamecheap    ProviderName = "namecheap"
	ProviderGoDaddy      ProviderName = "godaddy"
	ProviderHetzner      ProviderName = "hetzner"
	ProviderVultr        ProviderName = "vultr"
	ProviderAuto         ProviderName = "auto"
)

// DefaultProductionDirectory is the Let's Encrypt production ACME directory
const DefaultProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// DefaultStagingDirectory is the Let's Encrypt staging ACME directory
const DefaultStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// GetSupportedProviders returns a list of supported DNS providers
func GetSupportedProviders() []ProviderName {
	return []ProviderName{
		ProviderCloudflare,
		ProviderRoute53,
		ProviderDigitalOcean,
		ProviderGoogleCloud,
		ProviderNamecheap,
		ProviderGoDaddy,
		ProviderHetzner,
		ProviderVultr,
		ProviderAuto,
	}
}

// ParseProviderName parses a string into a ProviderName
func ParseProviderName(s string) (ProviderName, error) {
	switch strings.ToLower(s) {
	case "cloudflare", "cf":
		return ProviderCloudflare, nil
	case "route53", "aws", "r53":
		return ProviderRoute53, nil
	case "digitalocean", "do":
		return ProviderDigitalOcean, nil
	case "gcloud", "google", "gcp", "googledns":
		return ProviderGoogleCloud, nil
	case "namecheap", "nc":
		return ProviderNamecheap, nil
	case "godaddy", "gd":
		return ProviderGoDaddy, nil
	case "hetzner", "hz":
		return ProviderHetzner, nil
	case "vultr", "vr":
		return ProviderVultr, nil
	case "auto", "":
		return ProviderAuto, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrProviderNotSupported, s)
	}
}

// CheckEnvVars checks if the required environment variables are set
func CheckEnvVars(vars []string) error {
	var missing []string
	for _, v := range vars {
		if os.Getenv(v) == "" {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingCredentials, strings.Join(missing, ", "))
	}
	return nil
}
