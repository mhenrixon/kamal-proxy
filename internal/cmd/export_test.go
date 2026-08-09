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

// runExportCerts executes `export certs` with the given args and returns the
// combined output. The socket is pointed at nowhere so the command always
// falls back to the offline path.
func runExportCerts(t *testing.T, args ...string) (string, error) {
	t.Helper()

	t.Setenv("KAMAL_PROXY_SOCKET", filepath.Join(t.TempDir(), "no-proxy.sock"))

	previousConfig := globalConfig
	t.Cleanup(func() {
		globalConfig = previousConfig
	})
	globalConfig = server.Config{}
	cmd := newExportCommand().cmd

	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(append([]string{"certs"}, args...))

	err := cmd.Execute()
	return out.String(), err
}

// seedCertStore writes a minimal but valid store into dir.
func seedCertStore(t *testing.T, dir string) {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.state"),
		[]byte(`{"certificates":{},"domain_map":{},"saved_at":"2026-08-09T00:00:00Z"}`), 0600))
}

func TestExportCertsCommand_RequiresAnOutputPath(t *testing.T) {
	_, err := runExportCerts(t)
	require.Error(t, err)
}

func TestExportCertsCommand_ExportsOffline(t *testing.T) {
	dir := t.TempDir()
	seedCertStore(t, dir)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	out, err := runExportCerts(t, archivePath, "--data-dir", dir)
	require.NoError(t, err)

	assert.Contains(t, out, "offline")
	assert.Contains(t, out, "Exported 0 certificates (0 domains)")
	assert.FileExists(t, archivePath)
}

func TestExportCertsCommand_EmptyStoreFails(t *testing.T) {
	_, err := runExportCerts(t, filepath.Join(t.TempDir(), "backup.tar.gz"), "--data-dir", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestImportCertsCommand_ArchiveRestoreRoundTrip(t *testing.T) {
	source := t.TempDir()
	seedCertStore(t, source)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	_, err := runExportCerts(t, archivePath, "--data-dir", source)
	require.NoError(t, err)

	// Restore into an empty data dir.
	target := t.TempDir()
	out, err := runImportCerts(t, "--archive", archivePath, "--data-dir", target)
	require.NoError(t, err)
	assert.Contains(t, out, "Restored 0 certificates (0 domains)")
	assert.FileExists(t, filepath.Join(target, "acme.state"))

	// A second restore refuses the now non-empty store...
	_, err = runImportCerts(t, "--archive", archivePath, "--data-dir", target)
	require.ErrorIs(t, err, server.ErrCertStoreNotEmpty)

	// ...unless forced.
	_, err = runImportCerts(t, "--archive", archivePath, "--data-dir", target, "--force")
	require.NoError(t, err)
}

func TestImportCertsCommand_VerifyReportsWithoutWriting(t *testing.T) {
	source := t.TempDir()
	seedCertStore(t, source)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	_, err := runExportCerts(t, archivePath, "--data-dir", source)
	require.NoError(t, err)

	target := t.TempDir()
	out, err := runImportCerts(t, "--archive", archivePath, "--verify", "--data-dir", target)
	require.NoError(t, err)

	assert.Contains(t, out, "Certificates: 0")
	assert.NoFileExists(t, filepath.Join(target, "acme.state"),
		"--verify must not touch the store")
}

func TestImportCertsCommand_FlagValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "archive and traefik-acme are exclusive", args: []string{"--archive", "a.tar.gz", "--traefik-acme", "acme.json"}},
		{name: "resolver applies only to traefik", args: []string{"--archive", "a.tar.gz", "--resolver", "le"}},
		{name: "verify requires archive", args: []string{"--traefik-acme", "acme.json", "--verify"}},
		{name: "verify and force are exclusive", args: []string{"--archive", "a.tar.gz", "--verify", "--force"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runImportCerts(t, tt.args...)
			require.Error(t, err)
		})
	}
}
