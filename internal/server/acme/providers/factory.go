package providers

import (
	"fmt"
	"os"
	"strings"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/go-acme/lego/v4/challenge"
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
	info := make(map[acme.ProviderName]ProviderInfo, len(registry))
	for name, provider := range registry {
		info[name] = ProviderInfo{
			Name:            name,
			DisplayName:     provider.DisplayName,
			RequiredEnvVars: provider.Required,
			OptionalEnvVars: append([]string{}, provider.Optional...),
			Documentation:   provider.Docs,
		}
	}
	return info
}

// NewProvider creates a DNS provider based on the provider name
func NewProvider(name acme.ProviderName) (challenge.Provider, error) {
	if name == acme.ProviderAuto {
		return autoDetectProvider()
	}

	provider, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", acme.ErrProviderNotSupported, name)
	}

	if !provider.NoBootCheck && !anySetSatisfied(provider.credentialSets()) {
		return nil, fmt.Errorf("%w: need %s", acme.ErrMissingCredentials,
			describeSets(provider.credentialSets()))
	}

	return provider.New()
}

// autoDetectProvider attempts to auto-detect the DNS provider from environment variables
func autoDetectProvider() (challenge.Provider, error) {
	for _, name := range detectionOrder {
		provider, err := NewProvider(name)
		if err == nil {
			return provider, nil
		}
	}

	return nil, fmt.Errorf("%w: could not auto-detect DNS provider from environment", acme.ErrProviderNotConfigured)
}

// DetectProviderName detects which provider is configured from environment variables
func DetectProviderName() (acme.ProviderName, bool) {
	for _, name := range detectionOrder {
		if anySetSatisfied(registry[name].detectSets()) {
			return name, true
		}
	}

	return "", false
}

// anySetSatisfied reports whether any one AND-set of env vars is fully present.
func anySetSatisfied(sets [][]string) bool {
	for _, set := range sets {
		if len(set) == 0 {
			continue
		}
		satisfied := true
		for _, envVar := range set {
			if os.Getenv(envVar) == "" {
				satisfied = false
				break
			}
		}
		if satisfied {
			return true
		}
	}
	return false
}

// describeSets renders an OR-of-ANDs credential rule for an error message,
// e.g. "CF_API_TOKEN or CF_DNS_API_TOKEN or (CF_API_KEY + CF_API_EMAIL)".
func describeSets(sets [][]string) string {
	parts := make([]string, 0, len(sets))
	for _, set := range sets {
		if len(set) == 1 {
			parts = append(parts, set[0])
		} else {
			parts = append(parts, "("+strings.Join(set, " + ")+")")
		}
	}
	return strings.Join(parts, " or ")
}
