package providers

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

func TestNames_CoversRegistryExactlySorted(t *testing.T) {
	names := Names()

	require.Len(t, names, len(registry))
	for _, name := range names {
		assert.Contains(t, registry, name)
	}
	assert.IsIncreasing(t, names)
}

func TestProviderTableMarkdown_RendersEveryRegistryEntry(t *testing.T) {
	table := ProviderTableMarkdown()

	for name, provider := range registry {
		assert.Contains(t, table, "| `"+string(name)+"` | ["+provider.DisplayName+"]("+provider.Docs+")",
			"provider %s must appear with its flag value and docs link", name)
	}

	// The credential column renders the full OR-of-ANDs rule, not prose:
	// Cloudflare's third alternative was exactly what the hand-written table
	// had already lost.
	assert.Contains(t, table,
		"`CF_DNS_API_TOKEN` or `CLOUDFLARE_DNS_API_TOKEN` or (`CF_API_KEY` + `CF_API_EMAIL`) or (`CLOUDFLARE_API_KEY` + `CLOUDFLARE_EMAIL`)")
	assert.Contains(t, table, "`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`")

	// Optional vars come from the registry entry, not prose.
	assert.Contains(t, table, "`NAMECHEAP_SANDBOX`")

	// Deterministic: two renders are identical.
	assert.Equal(t, table, ProviderTableMarkdown())
}

func TestReplaceProviderTable_RewritesOnlyTheMarkedBlock(t *testing.T) {
	doc := "before\n" + providerTableBeginMarker + "\nstale table\n" + providerTableEndMarker + "\nafter\n"

	replaced, err := ReplaceProviderTable(doc)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(replaced, "before\n"))
	assert.True(t, strings.HasSuffix(replaced, "\nafter\n"))
	assert.NotContains(t, replaced, "stale table")
	assert.Contains(t, replaced, ProviderTableMarkdown())

	// Idempotent: replacing again changes nothing.
	again, err := ReplaceProviderTable(replaced)
	require.NoError(t, err)
	assert.Equal(t, replaced, again)
}

func TestReplaceProviderTable_FailsWithoutMarkers(t *testing.T) {
	_, err := ReplaceProviderTable("a document with no markers")
	require.Error(t, err)
}

// The committed README table must match what the registry renders; a provider
// added to the registry without regenerating fails here, named.
func TestREADMEProviderTable_MatchesRegistry(t *testing.T) {
	data, err := os.ReadFile("../../../../README.md")
	require.NoError(t, err)

	regenerated, err := ReplaceProviderTable(string(data))
	require.NoError(t, err, "README.md must carry the provider table markers")

	if string(data) == regenerated {
		return
	}

	// Name the rows the registry renders that the committed table lacks —
	// a brand-new provider AND a changed row (credentials, optional vars)
	// both surface as an expected line the document does not contain.
	stale := []string{}
	for line := range strings.Lines(ProviderTableMarkdown()) {
		line = strings.TrimSuffix(line, "\n")
		if line != "" && !strings.Contains(string(data), line) {
			stale = append(stale, line)
		}
	}
	t.Fatalf("README.md provider table is out of date (run `go generate ./internal/server/acme/providers`); stale or missing rows:\n%s",
		strings.Join(stale, "\n"))
}

// The flag help must enumerate the registry, plus the auto pseudo-provider,
// with no hand-maintained copy anywhere.
func TestProviderListForHelp_MatchesRegistry(t *testing.T) {
	help := ProviderListForHelp()

	for name := range registry {
		assert.Contains(t, help, string(name))
	}
	assert.True(t, strings.HasSuffix(help, ", "+string(acme.ProviderAuto)+", none"),
		"the auto and none pseudo-providers follow the registry names")
}
