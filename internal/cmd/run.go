package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

type runCommand struct {
	cmd              *cobra.Command
	debugLogsEnabled bool
	acmeDNSProvider  string
}

func newRunCommand() *runCommand {
	runCommand := &runCommand{}
	runCommand.cmd = &cobra.Command{
		Use:   "run",
		Short: "Run the server",
		RunE:  runCommand.run,
	}

	runCommand.cmd.Flags().BoolVar(&runCommand.debugLogsEnabled, "debug", getEnvBool("DEBUG", false), "Include debugging logs")
	runCommand.cmd.Flags().IntVar(&globalConfig.HttpPort, "http-port", getEnvInt("HTTP_PORT", server.DefaultHttpPort), "Port to serve HTTP traffic on")
	runCommand.cmd.Flags().IntVar(&globalConfig.HttpsPort, "https-port", getEnvInt("HTTPS_PORT", server.DefaultHttpsPort), "Port to serve HTTPS traffic on")
	runCommand.cmd.Flags().IntVar(&globalConfig.MetricsPort, "metrics-port", getEnvInt("METRICS_PORT", 0), "Publish metrics on the specified port (default zero to disable)")
	runCommand.cmd.Flags().BoolVar(&globalConfig.HTTP3Enabled, "http3", false, "Enable HTTP/3")

	// ACME certificate management flags
	runCommand.cmd.Flags().StringVar(&globalConfig.ACMEEmail, "acme-email", getEnvString("ACME_EMAIL", ""), "Contact email for Let's Encrypt (enables automatic wildcard certs when DNS provider configured)")
	runCommand.cmd.Flags().StringVar(&runCommand.acmeDNSProvider, "acme-dns-provider", getEnvString("ACME_DNS_PROVIDER", "auto"), "DNS provider for DNS-01 challenges (cloudflare, route53, digitalocean, gcloud, namecheap, godaddy, hetzner, vultr, auto)")
	runCommand.cmd.Flags().StringVar(&globalConfig.ACMEDirectory, "acme-directory", getEnvString("ACME_DIRECTORY", ""), "ACME directory URL (defaults to Let's Encrypt production)")
	runCommand.cmd.Flags().BoolVar(&globalConfig.ACMEPreferWildcard, "acme-prefer-wildcard", getEnvBool("ACME_PREFER_WILDCARD", true), "Prefer wildcard certificates when DNS provider available")
	runCommand.cmd.Flags().BoolVar(&globalConfig.ACMEHTTPFallback, "acme-http-fallback", getEnvBool("ACME_HTTP_FALLBACK", true), "Fall back to HTTP-01 challenge if DNS-01 fails")

	return runCommand
}

func (c *runCommand) run(cmd *cobra.Command, args []string) error {
	c.setLogger()

	// Parse DNS provider if specified
	if c.acmeDNSProvider != "" {
		providerName, err := acme.ParseProviderName(c.acmeDNSProvider)
		if err != nil {
			slog.Warn("Invalid DNS provider specified", "provider", c.acmeDNSProvider, "error", err)
		} else {
			globalConfig.ACMEDNSProvider = providerName
		}
	}

	router := server.NewRouter(globalConfig.StatePath())
	router.RestoreLastSavedState()

	// Initialize certificate registry if ACME is configured
	if globalConfig.HasACMEConfig() {
		if err := c.initCertificateRegistry(router); err != nil {
			slog.Error("Failed to initialize certificate registry", "error", err)
			// Continue without registry - will fall back to per-service certs
		}
	}

	s := server.NewServer(&globalConfig, router)
	err := s.Start()
	if err != nil {
		return err
	}
	defer s.Stop()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch

	return nil
}

func (c *runCommand) initCertificateRegistry(router *server.Router) error {
	config := globalConfig.CertificateRegistryConfig()

	registry, err := server.NewCertificateRegistry(config)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := registry.Initialize(ctx); err != nil {
		return err
	}

	router.SetCertificateRegistry(registry)
	slog.Info("Certificate registry initialized",
		"email", config.Email,
		"dns_provider", config.DNSProvider,
		"prefer_wildcard", config.PreferWildcard,
	)

	return nil
}

func (c *runCommand) setLogger() {
	level := slog.LevelInfo
	if c.debugLogsEnabled {
		level = slog.LevelDebug
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}
