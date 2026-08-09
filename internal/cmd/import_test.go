package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server"
)

// runImportCerts executes `import certs` with the given args and returns the
// combined output.
func runImportCerts(t *testing.T, args ...string) (string, error) {
	t.Helper()

	previousConfig := globalConfig
	t.Cleanup(func() {
		globalConfig = previousConfig
	})
	globalConfig = server.Config{}
	cmd := newImportCommand().cmd

	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(append([]string{"certs"}, args...))

	err := cmd.Execute()
	return out.String(), err
}

func TestImportCertsCommand_RequiresTraefikAcmeFlag(t *testing.T) {
	_, err := runImportCerts(t)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "traefik-acme")
}

func TestImportCertsCommand_ImportsIntoTheDataDir(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	require.NoError(t, os.WriteFile(acmePath, []byte(`{}`), 0600))

	out, err := runImportCerts(t, "--traefik-acme", acmePath, "--data-dir", dir)
	require.NoError(t, err)

	// The summary is printed, and the state landed in the given data dir.
	assert.Contains(t, out, "Imported: 0")
	assert.FileExists(t, filepath.Join(dir, "acme.state"))
}

func TestImportCertsCommand_CreatesAMissingDataDir(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	require.NoError(t, os.WriteFile(acmePath, []byte(`{}`), 0600))

	// A first-boot import writes state even when nothing qualifies, so the
	// data dir must be created up front, as `run` does.
	dataDir := filepath.Join(dir, "brand", "new")
	_, err := runImportCerts(t, "--traefik-acme", acmePath, "--data-dir", dataDir)
	require.NoError(t, err)

	assert.FileExists(t, filepath.Join(dataDir, "acme.state"))
}

func TestImportCertsCommand_FailsOnUnparseableInput(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	require.NoError(t, os.WriteFile(acmePath, []byte(`{not json`), 0600))

	_, err := runImportCerts(t, "--traefik-acme", acmePath, "--data-dir", dir)
	require.Error(t, err)
}

func TestImportCertsCommand_FailsOnUnknownResolver(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	require.NoError(t, os.WriteFile(acmePath, []byte(`{}`), 0600))

	_, err := runImportCerts(t, "--traefik-acme", acmePath, "--data-dir", dir, "--resolver", "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}
