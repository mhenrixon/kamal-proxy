package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/basecamp/kamal-proxy/internal/server/acme/providers"
)

// The --acme-dns-provider help enumerates the registry, not a hand-written
// list: a provider added to the registry appears here with no other change.
func TestRunCommand_DNSProviderHelpMatchesRegistry(t *testing.T) {
	flag := newRunCommand().cmd.Flags().Lookup("acme-dns-provider")
	require.NotNil(t, flag)

	for _, name := range providers.Names() {
		assert.Contains(t, flag.Usage, string(name))
	}
	assert.Contains(t, flag.Usage, string(acme.ProviderAuto))
}
