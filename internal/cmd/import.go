package cmd

import (
	"fmt"
	"strings"
	"time"

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
		Short: "Import certificates into the certificate store",
	}

	importCommand.cmd.AddCommand(newImportCertsCommand().cmd)

	return importCommand
}

// importCertsCommand seeds the certificate store from an external source: a
// Traefik acme.json (--traefik-acme) or a certificate store archive written by
// `export certs` (--archive). Both run offline against the data directory --
// no RPC socket, no running server -- so restores follow the runbook: stop the
// proxy, import, start it again.
type importCertsCommand struct {
	cmd *cobra.Command

	traefikAcmePath string
	resolver        string

	archivePath string
	force       bool
	verify      bool
}

func newImportCertsCommand() *importCertsCommand {
	importCertsCommand := &importCertsCommand{}
	importCertsCommand.cmd = &cobra.Command{
		Use:   "certs",
		Short: "Import certificates from a Traefik acme.json, or restore an exported certificate store archive",
		RunE:  importCertsCommand.run,
		Args:  cobra.NoArgs,
	}

	flags := importCertsCommand.cmd.Flags()
	flags.StringVar(&importCertsCommand.traefikAcmePath, "traefik-acme", "", "Path to the Traefik acme.json to import from")
	flags.StringVar(&importCertsCommand.resolver, "resolver", "", "Import only this resolver's certificates (default all resolvers, last writer wins per domain)")
	flags.StringVar(&importCertsCommand.archivePath, "archive", "", "Path to a certificate store archive written by `export certs`")
	flags.BoolVar(&importCertsCommand.force, "force", false, "Overwrite a non-empty certificate store when restoring an archive")
	flags.BoolVar(&importCertsCommand.verify, "verify", false, "Only verify the archive: parse every certificate and report domains and expiries, without touching the store")
	flags.StringVar(&globalConfig.AlternateConfigDir, "data-dir", getEnvString("DATA_DIR", ""), "Directory for state and certificate storage (default $HOME/.config/dash-proxy)")

	importCertsCommand.cmd.MarkFlagsOneRequired("traefik-acme", "archive")
	importCertsCommand.cmd.MarkFlagsMutuallyExclusive("traefik-acme", "archive")
	importCertsCommand.cmd.MarkFlagsMutuallyExclusive("archive", "resolver")
	// --verify and --force are archive-only and meaningless for a Traefik
	// import; grouping traefik-acme with them makes cobra reject those
	// combinations while still allowing --archive with either.
	importCertsCommand.cmd.MarkFlagsMutuallyExclusive("verify", "force", "traefik-acme")

	return importCertsCommand
}

func (c *importCertsCommand) run(cmd *cobra.Command, args []string) error {
	// The flag groups guarantee --verify comes with --archive: one of
	// traefik-acme/archive is required, and verify excludes traefik-acme.
	if c.verify {
		return c.runVerify(cmd)
	}

	if c.archivePath != "" {
		return c.runRestore(cmd)
	}

	return c.runTraefikImport(cmd)
}

func (c *importCertsCommand) runTraefikImport(cmd *cobra.Command) error {
	// A fresh --data-dir must exist before the state file is written into it —
	// an import with zero certificates still writes state.
	if err := ensureDataDir(); err != nil {
		return err
	}

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

func (c *importCertsCommand) runRestore(cmd *cobra.Command) error {
	if err := ensureDataDir(); err != nil {
		return err
	}

	summary, err := server.RestoreCertificateStore(server.CertStoreRestoreOptions{
		ArchivePath: c.archivePath,
		Paths:       globalConfig.CertStorePaths(),
		Force:       c.force,
	})
	if err != nil {
		return err
	}

	for _, warning := range summary.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARN %s\n", warning)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Restored %d certificates (%d domains)\nAccount key: %s\nDynamic domains state: %s\n",
		summary.Certificates, summary.Domains,
		restoredWord(summary.AccountKeyRestored), restoredWord(summary.DynamicDomainsRestored))

	return nil
}

func (c *importCertsCommand) runVerify(cmd *cobra.Command) error {
	report, err := server.VerifyCertificateArchive(c.archivePath)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	expired := 0
	for _, cert := range report.Certificates {
		if cert.NotAfter.Before(time.Now()) {
			expired++
		}
		fmt.Fprintf(out, "%s  expires %s  %s\n",
			cert.Identifier, cert.NotAfter.Format("2006-01-02"), strings.Join(cert.Domains, " "))
	}

	for _, warning := range report.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARN %s\n", warning)
	}

	fmt.Fprintf(out, "Certificates: %d (%d expired)\nDomain mappings: %d\nAccount key: %s\nDynamic domains state: %s\n",
		len(report.Certificates), expired, report.DomainMappings,
		presentWord(report.HasAccountKey), presentWord(report.HasDynamicDomains))

	return nil
}

func restoredWord(restored bool) string {
	if restored {
		return "restored"
	}
	return "not in archive"
}

func presentWord(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}
