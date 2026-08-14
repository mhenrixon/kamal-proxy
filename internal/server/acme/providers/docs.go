package providers

import (
	"fmt"
	"slices"
	"strings"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

// Documentation derived from the registry: the --acme-dns-provider help list,
// the README's supported-provider table, and the marker-based replacement
// shared by the generator tool and the drift test. The registry is the single
// source of truth; nothing here is hand-maintained.

//go:generate go run ./gen

const (
	providerTableBeginMarker = "<!-- BEGIN GENERATED: dns-provider-table (go generate ./internal/server/acme/providers) -->"
	providerTableEndMarker   = "<!-- END GENERATED: dns-provider-table -->"
)

// Names returns every registered provider name, sorted.
func Names() []acme.ProviderName {
	names := make([]acme.ProviderName, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ProviderListForHelp renders the provider names for the --acme-dns-provider
// flag help: the registry, sorted, plus the auto pseudo-provider.
func ProviderListForHelp() string {
	parts := make([]string, 0, len(registry)+1)
	for _, name := range Names() {
		parts = append(parts, string(name))
	}
	parts = append(parts, string(acme.ProviderAuto))
	return strings.Join(parts, ", ")
}

// ProviderTableMarkdown renders the supported-provider table: one row per
// registry entry, leading with the name the --acme-dns-provider flag accepts
// (a display name like "AWS Route53" is not a flag value), then the display
// name linked to its lego documentation, the credential rule as the same
// OR-of-ANDs the boot check enforces, and the optional variables the entry
// names.
func ProviderTableMarkdown() string {
	var b strings.Builder
	b.WriteString("| Name | Provider | Credentials | Optional |\n")
	b.WriteString("|------|----------|-------------|----------|\n")

	for _, name := range Names() {
		provider := registry[name]
		fmt.Fprintf(&b, "| `%s` | [%s](%s) | %s | %s |\n",
			name, provider.DisplayName, provider.Docs,
			markdownCredentialSets(provider.credentialSets()),
			markdownVars(provider.Optional))
	}

	return b.String()
}

// ReplaceProviderTable substitutes the generated provider table between the
// README's markers, leaving everything else untouched. It errors when the
// markers are missing — silently appending a table nobody asked for is how a
// generator corrupts a document.
func ReplaceProviderTable(document string) (string, error) {
	begin := strings.Index(document, providerTableBeginMarker)
	end := strings.Index(document, providerTableEndMarker)
	if begin == -1 || end == -1 || end < begin {
		return "", fmt.Errorf("provider table markers not found (need %q ... %q)",
			providerTableBeginMarker, providerTableEndMarker)
	}

	return document[:begin+len(providerTableBeginMarker)] +
		"\n" + ProviderTableMarkdown() +
		document[end:], nil
}

// markdownCredentialSets renders an OR-of-ANDs credential rule with each
// variable in backticks, e.g. "`CF_API_TOKEN` or (`CF_API_KEY` + `CF_API_EMAIL`)".
func markdownCredentialSets(sets [][]string) string {
	parts := make([]string, 0, len(sets))
	for _, set := range sets {
		joined := make([]string, 0, len(set))
		for _, envVar := range set {
			joined = append(joined, "`"+envVar+"`")
		}
		if len(set) > 1 {
			parts = append(parts, "("+strings.Join(joined, " + ")+")")
		} else {
			parts = append(parts, strings.Join(joined, " + "))
		}
	}
	return strings.Join(parts, " or ")
}

// markdownVars renders a plain list of env vars in backticks, or a dash for
// none.
func markdownVars(vars []string) string {
	if len(vars) == 0 {
		return "—"
	}
	quoted := make([]string, 0, len(vars))
	for _, envVar := range vars {
		quoted = append(quoted, "`"+envVar+"`")
	}
	return strings.Join(quoted, ", ")
}
