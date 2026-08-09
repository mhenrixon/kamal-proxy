package acme

import (
	"fmt"
	"strings"
)

// ProviderSelection is the parsed form of --acme-dns-provider: explicit
// zone→provider mappings, plus a default provider for unmatched zones. A
// fleet whose wildcard zones live at different DNS hosts maps each zone to
// its host; the single-provider form is just a selection with no zones.
type ProviderSelection struct {
	// Default answers for domains no zone matches. Empty means no DNS-01
	// provider for unmatched zones, leaving them on HTTP-01.
	Default ProviderName

	// Zones maps a DNS zone (a domain suffix, matched on label boundaries)
	// to the provider that can answer DNS-01 for it.
	Zones map[string]ProviderName
}

// HasZones reports whether any explicit zone mappings are configured.
func (s ProviderSelection) HasZones() bool {
	return len(s.Zones) > 0
}

// ProviderFor selects the provider for a domain: the longest configured zone
// that matches by suffix on label boundaries wins, else the default. The
// returned zone is empty when the default (or nothing) answered; it doubles
// as a partition key for keeping one ACME order on one provider.
func (s ProviderSelection) ProviderFor(domain string) (ProviderName, string) {
	candidate := normalizeZone(domain)

	bestZone := ""
	var best ProviderName
	for zone, provider := range s.Zones {
		if candidate != zone && !strings.HasSuffix(candidate, "."+zone) {
			continue
		}
		if len(zone) > len(bestZone) {
			bestZone, best = zone, provider
		}
	}

	if bestZone != "" {
		return best, bestZone
	}
	return s.Default, ""
}

// ParseProviderEntries parses --acme-dns-provider values. Each entry is
// either a bare provider name, which becomes the default for unmatched zones
// (at most one), or a zone=provider mapping. Mappings are always explicit:
// "auto" picks the single default from visible credentials, so it cannot be
// mapped to a zone.
func ParseProviderEntries(entries []string) (ProviderSelection, error) {
	selection := ProviderSelection{Zones: map[string]ProviderName{}}
	haveDefault := false

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		zone, value, mapped := strings.Cut(entry, "=")
		if !mapped {
			name, err := ParseProviderName(entry)
			if err != nil {
				return ProviderSelection{}, err
			}
			if haveDefault {
				return ProviderSelection{}, fmt.Errorf("multiple default DNS providers: %q and %q", selection.Default, name)
			}
			selection.Default = name
			haveDefault = true
			continue
		}

		zone = normalizeZone(zone)
		if zone == "" {
			return ProviderSelection{}, fmt.Errorf("empty zone in DNS provider mapping %q", entry)
		}

		name, err := ParseProviderName(value)
		if err != nil {
			return ProviderSelection{}, fmt.Errorf("zone %q: %w", zone, err)
		}
		if name == ProviderAuto {
			return ProviderSelection{}, fmt.Errorf("zone %q: mappings are always explicit; %q cannot be mapped to a zone", zone, "auto")
		}

		if _, ok := selection.Zones[zone]; ok {
			return ProviderSelection{}, fmt.Errorf("duplicate zone in DNS provider mappings: %q", zone)
		}
		selection.Zones[zone] = name
	}

	return selection, nil
}

// normalizeZone lowercases a zone or domain and strips a wildcard prefix and
// trailing dot, so "*.Platform.Example." and "app.platform.example" compare
// in the same space.
func normalizeZone(zone string) string {
	zone = strings.ToLower(strings.TrimSpace(zone))
	zone = strings.TrimPrefix(zone, "*.")
	return strings.TrimSuffix(zone, ".")
}
