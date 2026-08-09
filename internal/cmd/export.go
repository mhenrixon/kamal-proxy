package cmd

import (
	"fmt"
	"net/rpc"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type exportCommand struct {
	cmd *cobra.Command
}

func newExportCommand() *exportCommand {
	exportCommand := &exportCommand{}
	exportCommand.cmd = &cobra.Command{
		Use:   "export",
		Short: "Export proxy state for backup",
	}

	exportCommand.cmd.AddCommand(newExportCertsCommand().cmd)

	return exportCommand
}

// exportCertsCommand archives the certificate store for disaster recovery.
// Against a running proxy it exports over the RPC socket, under the same lock
// the certificate managers use for writes, so a backup taken mid-renewal is
// never torn. Without a reachable proxy it falls back to reading the data
// directory offline -- only safe when the proxy is actually stopped.
type exportCertsCommand struct {
	cmd *cobra.Command
}

func newExportCertsCommand() *exportCertsCommand {
	exportCertsCommand := &exportCertsCommand{}
	exportCertsCommand.cmd = &cobra.Command{
		Use:   "certs [output-path]",
		Short: "Export the certificate store to an archive for disaster recovery",
		Long: "Export the certificate store -- ACME account key, issued certificates,\n" +
			"domain mappings, and dynamic domain state -- to a gzipped tar archive.\n\n" +
			"With the proxy running, the snapshot is taken through the proxy under its\n" +
			"certificate write lock. With no proxy reachable on the socket, the data\n" +
			"directory is read directly; only do that with the proxy stopped.\n\n" +
			"The archive contains PRIVATE KEYS (certificate keys and the ACME account\n" +
			"key). It is written with mode 0600; store and transfer it accordingly.",
		RunE: exportCertsCommand.run,
		Args: cobra.ExactArgs(1),
	}

	exportCertsCommand.cmd.Flags().StringVar(&globalConfig.AlternateConfigDir, "data-dir", getEnvString("DATA_DIR", ""), "Directory for state and certificate storage (default $HOME/.config/kamal-proxy)")

	return exportCertsCommand
}

func (c *exportCertsCommand) run(cmd *cobra.Command, args []string) error {
	outputPath, err := filepath.Abs(args[0])
	if err != nil {
		return fmt.Errorf("failed to resolve the output path: %w", err)
	}

	summary, err := c.export(cmd, outputPath)
	if err != nil {
		return err
	}

	for _, warning := range summary.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARN %s\n", warning)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Exported %d certificates (%d domains) to %s\n",
		summary.Certificates, summary.Domains, outputPath)

	return nil
}

// export snapshots through the running proxy when the socket answers, and
// falls back to reading the data directory offline when it does not.
func (c *exportCertsCommand) export(cmd *cobra.Command, outputPath string) (server.CertsExportSummary, error) {
	var summary server.CertsExportSummary

	client, dialErr := rpc.Dial("unix", globalConfig.SocketPath())
	if dialErr == nil {
		defer client.Close()
		err := client.Call("kamal-proxy.CertsExport", server.CertsExportArgs{Path: outputPath}, &summary)
		return summary, err
	}

	fmt.Fprintln(cmd.ErrOrStderr(), "Proxy is not running; exporting offline from the data directory")
	return server.ExportCertificateStore(globalConfig.CertStorePaths(), outputPath)
}
