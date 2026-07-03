package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

var (
	ErrProviderNotConfigured   = errors.New("DNS provider not configured")
	ErrProviderNotSupported    = errors.New("DNS provider not supported")
	ErrMissingCredentials      = errors.New("missing required credentials for DNS provider")
	ErrRegistrationFailed      = errors.New("ACME registration failed")
	ErrCertificateObtainFailed = errors.New("failed to obtain certificate")
)

// ProviderName represents a supported DNS provider
type ProviderName string

const (
	ProviderCloudflare   ProviderName = "cloudflare"
	ProviderRoute53      ProviderName = "route53"
	ProviderDigitalOcean ProviderName = "digitalocean"
	ProviderGoogleCloud  ProviderName = "gcloud"
	ProviderNamecheap    ProviderName = "namecheap"
	ProviderGoDaddy      ProviderName = "godaddy"
	ProviderHetzner      ProviderName = "hetzner"
	ProviderVultr        ProviderName = "vultr"
	ProviderAuto         ProviderName = "auto"
)

// ACMEConfig holds the configuration for ACME certificate provisioning
type ACMEConfig struct {
	Email           string       // Contact email for Let's Encrypt
	Directory       string       // ACME directory URL (production or staging)
	DNSProvider     ProviderName // DNS provider to use
	PreferWildcard  bool         // Prefer wildcard certs when possible
	PropagationWait int          // Seconds to wait for DNS propagation (0 = auto)
}

// DefaultProductionDirectory is the Let's Encrypt production ACME directory
const DefaultProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// DefaultStagingDirectory is the Let's Encrypt staging ACME directory
const DefaultStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// ACMEUser implements the lego registration.User interface
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// DNSProviderFactory creates DNS challenge providers
type DNSProviderFactory interface {
	// NewProvider creates a new DNS challenge provider from environment variables
	NewProvider() (challenge.Provider, error)
	// Name returns the provider name
	Name() ProviderName
	// RequiredEnvVars returns the environment variables required for this provider
	RequiredEnvVars() []string
}

// ACMEClient wraps lego for certificate operations
type ACMEClient struct {
	config      ACMEConfig
	user        *ACMEUser
	client      *lego.Client
	dnsProvider challenge.Provider
}

// NewACMEClient creates a new ACME client for DNS-01 challenges
func NewACMEClient(config ACMEConfig) (*ACMEClient, error) {
	if config.Email == "" {
		return nil, fmt.Errorf("ACME email is required")
	}

	if config.Directory == "" {
		config.Directory = DefaultProductionDirectory
	}

	// Generate a new private key for ACME account
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	user := &ACMEUser{
		Email: config.Email,
		key:   privateKey,
	}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = config.Directory
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	return &ACMEClient{
		config: config,
		user:   user,
		client: client,
	}, nil
}

// SetDNSProvider sets the DNS provider for DNS-01 challenges
func (c *ACMEClient) SetDNSProvider(provider challenge.Provider) error {
	c.dnsProvider = provider

	opts := []dns01.ChallengeOption{}
	if c.config.PropagationWait > 0 {
		// Use sequential resolver with custom wait time
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}

	return c.client.Challenge.SetDNS01Provider(provider, opts...)
}

// Register registers the ACME account
func (c *ACMEClient) Register(ctx context.Context) error {
	reg, err := c.client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}
	c.user.Registration = reg
	slog.Info("ACME account registered", "email", c.user.Email)
	return nil
}

// ObtainCertificate obtains a certificate for the given domains
func (c *ACMEClient) ObtainCertificate(ctx context.Context, domains []string) (*certificate.Resource, error) {
	if c.dnsProvider == nil {
		return nil, ErrProviderNotConfigured
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	slog.Info("Obtaining certificate", "domains", domains)

	cert, err := c.client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificateObtainFailed, err)
	}

	slog.Info("Certificate obtained successfully", "domains", domains)
	return cert, nil
}

// RenewCertificate renews an existing certificate
func (c *ACMEClient) RenewCertificate(ctx context.Context, cert *certificate.Resource) (*certificate.Resource, error) {
	if c.dnsProvider == nil {
		return nil, ErrProviderNotConfigured
	}

	slog.Info("Renewing certificate", "domains", cert.Domain)

	newCert, err := c.client.Certificate.RenewWithOptions(*cert, &certificate.RenewOptions{Bundle: true})
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	slog.Info("Certificate renewed successfully", "domains", cert.Domain)
	return newCert, nil
}

// GetSupportedProviders returns a list of supported DNS providers
func GetSupportedProviders() []ProviderName {
	return []ProviderName{
		ProviderCloudflare,
		ProviderRoute53,
		ProviderDigitalOcean,
		ProviderGoogleCloud,
		ProviderNamecheap,
		ProviderGoDaddy,
		ProviderHetzner,
		ProviderVultr,
		ProviderAuto,
	}
}

// ParseProviderName parses a string into a ProviderName
func ParseProviderName(s string) (ProviderName, error) {
	switch strings.ToLower(s) {
	case "cloudflare", "cf":
		return ProviderCloudflare, nil
	case "route53", "aws", "r53":
		return ProviderRoute53, nil
	case "digitalocean", "do":
		return ProviderDigitalOcean, nil
	case "gcloud", "google", "gcp", "googledns":
		return ProviderGoogleCloud, nil
	case "namecheap", "nc":
		return ProviderNamecheap, nil
	case "godaddy", "gd":
		return ProviderGoDaddy, nil
	case "hetzner", "hz":
		return ProviderHetzner, nil
	case "vultr", "vr":
		return ProviderVultr, nil
	case "auto", "":
		return ProviderAuto, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrProviderNotSupported, s)
	}
}

// CheckEnvVars checks if the required environment variables are set
func CheckEnvVars(vars []string) error {
	var missing []string
	for _, v := range vars {
		if os.Getenv(v) == "" {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingCredentials, strings.Join(missing, ", "))
	}
	return nil
}
