package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
	"github.com/basecamp/kamal-proxy/internal/server/acme"
)

type runCommand struct {
	cmd                     *cobra.Command
	debugLogsEnabled        bool
	acmeDNSProvider         string
	ignoreRestoreErrors     bool
	recheckTargetsOnRestore bool
}

func newRunCommand() *runCommand {
	runCommand := &runCommand{}
	runCommand.cmd = &cobra.Command{
		Use:     "run",
		Short:   "Run the server",
		PreRunE: runCommand.preRun,
		RunE:    runCommand.run,
	}

	runCommand.cmd.Flags().BoolVar(&runCommand.debugLogsEnabled, "debug", getEnvBool("DEBUG", false), "Include debugging logs")
	runCommand.cmd.Flags().IntVar(&globalConfig.HttpPort, "http-port", getEnvInt("HTTP_PORT", server.DefaultHttpPort), "Port to serve HTTP traffic on")
	runCommand.cmd.Flags().IntVar(&globalConfig.HttpsPort, "https-port", getEnvInt("HTTPS_PORT", server.DefaultHttpsPort), "Port to serve HTTPS traffic on")
	runCommand.cmd.Flags().IntVar(&globalConfig.MetricsPort, "metrics-port", getEnvInt("METRICS_PORT", 0), "Publish metrics on the specified port (default zero to disable)")
	runCommand.cmd.Flags().StringSliceVar(&globalConfig.MetricsAllowIPs, "metrics-allow-ip", nil, "Serve the metrics endpoint only to these addresses or CIDR ranges (default empty, serve everyone that can reach the port)")
	runCommand.cmd.Flags().BoolVar(&globalConfig.HTTP3Enabled, "http3", false, "Enable HTTP/3")
	runCommand.cmd.Flags().BoolVar(&runCommand.ignoreRestoreErrors, "ignore-restore-errors", getEnvBool("IGNORE_RESTORE_ERRORS", false), "Boot with an empty routing state when restoring the saved state fails")
	runCommand.cmd.Flags().BoolVar(&runCommand.recheckTargetsOnRestore, "recheck-targets-on-restore", getEnvBool("RECHECK_TARGETS_ON_RESTORE", false), "Re-verify restored targets with health checks instead of assuming they are healthy")
	runCommand.cmd.Flags().StringVar(&globalConfig.AlternateConfigDir, "data-dir", getEnvString("DATA_DIR", ""), "Directory for state and certificate storage (default $HOME/.config/kamal-proxy)")
	runCommand.cmd.Flags().BoolVar(&globalConfig.ReusePort, "reuse-port", getEnvBool("REUSE_PORT", false), "Bind listeners with SO_REUSEPORT so an overlapping proxy generation can share the ports during a handoff")
	runCommand.cmd.Flags().BoolVar(&globalConfig.ProxyProtocol, "proxy-protocol", getEnvBool("PROXY_PROTOCOL", false), "Accept PROXY protocol v1/v2 headers on the HTTP and HTTPS listeners, preserving client addresses behind an L4 load balancer")
	runCommand.cmd.Flags().StringSliceVar(&globalConfig.ProxyProtocolAllowIPs, "proxy-protocol-allow-ip", nil, "Honor PROXY protocol headers only from these addresses or CIDR ranges (default empty, trust every peer that can reach the port)")

	// Listener connection timeouts
	runCommand.cmd.Flags().DurationVar(&globalConfig.ReadHeaderTimeout, "read-header-timeout", getEnvDuration("READ_HEADER_TIMEOUT", server.DefaultReadHeaderTimeout), "Maximum time a client may take to send request headers (zero to disable)")
	runCommand.cmd.Flags().DurationVar(&globalConfig.ReadTimeout, "read-timeout", getEnvDuration("READ_TIMEOUT", server.DefaultReadTimeout), "Maximum time to read an entire request, including the body (zero to disable; non-zero truncates slow uploads)")
	runCommand.cmd.Flags().DurationVar(&globalConfig.WriteTimeout, "write-timeout", getEnvDuration("WRITE_TIMEOUT", server.DefaultWriteTimeout), "Maximum time to write an entire response (zero to disable; non-zero truncates SSE and streaming responses)")
	runCommand.cmd.Flags().DurationVar(&globalConfig.IdleTimeout, "idle-timeout", getEnvDuration("IDLE_TIMEOUT", server.DefaultIdleTimeout), "Maximum time an idle keep-alive connection is kept open (zero to disable)")
	runCommand.cmd.Flags().DurationVar(&globalConfig.ShutdownTimeout, "shutdown-timeout", getEnvDuration("SHUTDOWN_TIMEOUT", server.DefaultShutdownTimeout), "Maximum time to wait for in-flight requests to drain on shutdown")

	// ACME/TLS configuration
	runCommand.cmd.Flags().StringVar(&globalConfig.MinTLS, "min-tls", getEnvString("MIN_TLS", server.DefaultMinTLSVersion), "Lowest TLS version the HTTPS listener will negotiate: 1.2 or 1.3 (TLS 1.0 and 1.1 cannot be enabled; HTTP/3 is always 1.3)")
	runCommand.cmd.Flags().StringVar(&globalConfig.ACMEEmail, "acme-email", getEnvString("ACME_EMAIL", ""), "Email address for ACME account registration (required for automatic TLS)")
	runCommand.cmd.Flags().StringVar(&globalConfig.ACMEDirectory, "acme-directory", getEnvString("ACME_DIRECTORY", server.LetsEncryptProduction), "ACME directory URL")
	runCommand.cmd.Flags().StringVar(&runCommand.acmeDNSProvider, "acme-dns-provider", getEnvString("ACME_DNS_PROVIDER", "auto"), "DNS provider for DNS-01 challenges (cloudflare, route53, digitalocean, gcloud, namecheap, godaddy, hetzner, vultr, auto)")
	runCommand.cmd.Flags().BoolVar(&globalConfig.ACMEPreferWildcard, "acme-prefer-wildcard", getEnvBool("ACME_PREFER_WILDCARD", true), "Prefer wildcard certificates when DNS provider available")
	runCommand.cmd.Flags().BoolVar(&globalConfig.ACMEHTTPFallback, "acme-http-fallback", getEnvBool("ACME_HTTP_FALLBACK", true), "Fall back to HTTP-01 challenge if DNS-01 fails")

	return runCommand
}

// preRun rejects a bad --min-tls before the command restores routing state or
// registers an ACME account, so a typo costs a millisecond rather than a round
// trip to Let's Encrypt. The listener parses it again at bind time.
func (c *runCommand) preRun(cmd *cobra.Command, args []string) error {
	if _, err := server.ParseMinTLSVersion(globalConfig.MinTLS); err != nil {
		return err
	}

	return nil
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

	if globalConfig.AlternateConfigDir != "" {
		if err := os.MkdirAll(globalConfig.AlternateConfigDir, 0700); err != nil {
			return fmt.Errorf("failed to create data directory %q: %w", globalConfig.AlternateConfigDir, err)
		}
	}

	router := server.NewRouter(globalConfig.StatePath())

	if c.recheckTargetsOnRestore {
		router.EnableTargetRecheckOnRestore()
	}

	if err := router.RestoreLastSavedState(); err != nil {
		if !c.ignoreRestoreErrors {
			return fmt.Errorf("failed to restore saved state (use --ignore-restore-errors to boot with no services): %w", err)
		}
		slog.Error("Continuing with empty routing state", "error", err)
	}

	var dynamicDomains *server.DynamicDomainManager

	if globalConfig.ACMEEmail != "" {
		manager, err := server.NewSANCertManager(server.SANCertManagerConfig{
			Email:     globalConfig.ACMEEmail,
			Directory: globalConfig.ACMEDirectory,
			CachePath: globalConfig.CertificatePath(),
			StatePath: globalConfig.ACMEStatePath(),
		})
		if err != nil {
			return err
		}

		if err := manager.Initialize(cmd.Context()); err != nil {
			return err
		}

		router.SetSANCertManager(manager)

		dynamicDomains = server.NewDynamicDomainManager(server.DynamicDomainConfig{
			StatePath:    globalConfig.DynamicDomainsStatePath(),
			RefreshToken: os.Getenv("KAMAL_PROXY_REFRESH_TOKEN"),
			SourceToken:  os.Getenv("KAMAL_PROXY_DOMAINS_TOKEN"),
		}, manager, router)

		router.SetDynamicDomainManager(dynamicDomains)
	}

	// Initialize certificate registry if ACME is configured
	var renewalManager *server.CertificateRenewalManager
	if globalConfig.HasACMEConfig() {
		manager, err := c.initCertificateRegistry(router)
		if err != nil {
			slog.Error("Failed to initialize certificate registry", "error", err)
			// Continue without registry - will fall back to per-service certs
		} else {
			renewalManager = manager
		}
	}

	s := server.NewServer(&globalConfig, router)
	err := s.Start()
	if err != nil {
		return err
	}
	defer s.Stop()

	if dynamicDomains != nil {
		// Start after the listeners are bound (pre-flight probes and HTTP-01
		// challenges route through them), and stop before they close so
		// in-flight orders can still validate during shutdown.
		dynamicDomains.Start()
		defer dynamicDomains.Stop()
	}

	if renewalManager != nil {
		// Start background renewal after the registry is ready; stop it during
		// shutdown so an in-flight renewal can settle before we exit.
		renewalManager.Start()
		defer renewalManager.Stop()
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-ch:
		// Converge on the drain path so SIGTERM and `kamal-proxy drain`
		// behave identically; the deferred Stop finishes the teardown.
		_ = s.BeginDrain(0)
	case <-s.ShutdownRequested():
	}

	return nil
}

func (c *runCommand) initCertificateRegistry(router *server.Router) (*server.CertificateRenewalManager, error) {
	config := globalConfig.CertificateRegistryConfig()

	registry, err := server.NewCertificateRegistry(config)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if err := registry.Initialize(ctx); err != nil {
		return nil, err
	}

	router.SetCertificateRegistry(registry)
	slog.Info("Certificate registry initialized",
		"email", config.Email,
		"dns_provider", config.DNSProvider,
		"prefer_wildcard", config.PreferWildcard,
	)

	return server.NewCertificateRenewalManager(registry), nil
}

func (c *runCommand) setLogger() {
	level := slog.LevelInfo
	if c.debugLogsEnabled {
		level = slog.LevelDebug
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}
