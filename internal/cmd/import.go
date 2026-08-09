package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type importCommand struct {
	cmd *cobra.Command
}

func newImportCommand() *importCommand {
	importCommand := &importCommand{}
	importCommand.cmd = &cobra.Command{
		Use:   "import",
		Short: "Import externally issued certificates",
	}

	importCommand.cmd.AddCommand(newImportCertsCommand().cmd)

	return importCommand
}

// importCertsCommand seeds the certificate store from a Traefik acme.json. It
// runs offline against the data directory before the proxy's first boot -- no
// RPC socket, no running server -- so a fleet cut over from Traefik serves TLS
// immediately instead of re-issuing its whole estate.
type importCertsCommand struct {
	cmd *cobra.Command

	traefikAcmePath string
	resolver        string
}

func newImportCertsCommand() *importCertsCommand {
	importCertsCommand := &importCertsCommand{}
	importCertsCommand.cmd = &cobra.Command{
		Use:   "certs",
		Short: "Import certificates from a Traefik acme.json into the certificate store",
		RunE:  importCertsCommand.run,
		Args:  cobra.NoArgs,
	}

	importCertsCommand.cmd.Flags().StringVar(&importCertsCommand.traefikAcmePath, "traefik-acme", "", "Path to the Traefik acme.json to import from (required)")
	importCertsCommand.cmd.Flags().StringVar(&importCertsCommand.resolver, "resolver", "", "Import only this resolver's certificates (default all resolvers, last writer wins per domain)")
	importCertsCommand.cmd.Flags().StringVar(&globalConfig.AlternateConfigDir, "data-dir", getEnvString("DATA_DIR", ""), "Directory for state and certificate storage (default $HOME/.config/kamal-proxy)")

	if err := importCertsCommand.cmd.MarkFlagRequired("traefik-acme"); err != nil {
		panic(err)
	}

	return importCertsCommand
}

func (c *importCertsCommand) run(cmd *cobra.Command, args []string) error {
	summary, err := server.ImportTraefikCertificates(server.TraefikImportOptions{
		ACMEPath:  c.traefikAcmePath,
		Resolver:  c.resolver,
		CertsPath: globalConfig.CertificatePath(),
		StatePath: globalConfig.ACMEStatePath(),
	})
	if err != nil {
		return err
	}

	for _, warning := range summary.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARN %s\n", warning)
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"Imported: %d\nSkipped (expired): %d\nSkipped (duplicate): %d\nFailed to parse: %d\n",
		summary.Imported, summary.SkippedExpired, summary.SkippedDuplicate, summary.FailedToParse)

	return nil
}
