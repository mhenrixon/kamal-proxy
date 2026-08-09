package providers

import (
	"github.com/basecamp/kamal-proxy/internal/server/acme"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/namecheap"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/providers/dns/vultr"
)

// Provider is one registry entry. Everything the factory used to spread across
// a switch, bespoke constructors, and two ordered lists derives from this
// table: GetProviderInfo flattens the env var fields, NewProvider runs the
// credential rule then New, and auto-detection walks detectionOrder against
// the same rule.
type Provider struct {
	DisplayName string

	// Required is the flat AND of env vars that satisfies the credential
	// check, and the "required" column in provider info. Alternatives, when
	// set, replaces it for the check: an OR of ANDs, any one inner set
	// suffices (Cloudflare's token-or-key+email rule).
	Required     []string
	Optional     []string
	Alternatives [][]string

	// NoBootCheck skips the credential check entirely: route53's AWS SDK
	// resolves credentials from the environment, shared config, or an IAM
	// role on its own, so an empty environment is not an error.
	NoBootCheck bool

	// Detect, when set, overrides the credential rule for auto-detection.
	// Route53 needs it because its check is skipped but detection still has
	// to key off something visible.
	Detect [][]string

	Docs string
	New  func() (challenge.Provider, error)
}

// credentialSets returns the OR-of-ANDs the credential check enforces.
func (p Provider) credentialSets() [][]string {
	if p.Alternatives != nil {
		return p.Alternatives
	}
	return [][]string{p.Required}
}

// detectSets returns the OR-of-ANDs auto-detection matches against.
func (p Provider) detectSets() [][]string {
	if p.Detect != nil {
		return p.Detect
	}
	if p.NoBootCheck {
		return nil
	}
	return p.credentialSets()
}

var registry = map[acme.ProviderName]Provider{
	acme.ProviderCloudflare: {
		DisplayName: "Cloudflare",
		Required:    []string{"CF_API_TOKEN"},
		Optional:    []string{"CF_API_EMAIL", "CF_API_KEY", "CF_DNS_API_TOKEN", "CF_ZONE_API_TOKEN"},
		Alternatives: [][]string{
			{"CF_API_TOKEN"},
			{"CF_DNS_API_TOKEN"},
			{"CF_API_KEY", "CF_API_EMAIL"},
		},
		Docs: "https://go-acme.github.io/lego/dns/cloudflare/",
		New:  func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
	},
	acme.ProviderRoute53: {
		DisplayName: "AWS Route53",
		Required:    []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		Optional:    []string{"AWS_REGION", "AWS_HOSTED_ZONE_ID", "AWS_PROFILE"},
		NoBootCheck: true,
		Detect: [][]string{
			{"AWS_ACCESS_KEY_ID"},
			{"AWS_PROFILE"},
		},
		Docs: "https://go-acme.github.io/lego/dns/route53/",
		New:  func() (challenge.Provider, error) { return route53.NewDNSProvider() },
	},
	acme.ProviderDigitalOcean: {
		DisplayName: "DigitalOcean",
		Required:    []string{"DO_AUTH_TOKEN"},
		Docs:        "https://go-acme.github.io/lego/dns/digitalocean/",
		New:         func() (challenge.Provider, error) { return digitalocean.NewDNSProvider() },
	},
	acme.ProviderGoogleCloud: {
		DisplayName: "Google Cloud DNS",
		Required:    []string{"GCE_PROJECT"},
		Optional:    []string{"GCE_SERVICE_ACCOUNT_FILE", "GOOGLE_APPLICATION_CREDENTIALS"},
		Docs:        "https://go-acme.github.io/lego/dns/gcloud/",
		New:         func() (challenge.Provider, error) { return gcloud.NewDNSProvider() },
	},
	acme.ProviderNamecheap: {
		DisplayName: "Namecheap",
		Required:    []string{"NAMECHEAP_API_USER", "NAMECHEAP_API_KEY"},
		Optional:    []string{"NAMECHEAP_SANDBOX"},
		Docs:        "https://go-acme.github.io/lego/dns/namecheap/",
		New:         func() (challenge.Provider, error) { return namecheap.NewDNSProvider() },
	},
	acme.ProviderGoDaddy: {
		DisplayName: "GoDaddy",
		Required:    []string{"GODADDY_API_KEY", "GODADDY_API_SECRET"},
		Docs:        "https://go-acme.github.io/lego/dns/godaddy/",
		New:         func() (challenge.Provider, error) { return godaddy.NewDNSProvider() },
	},
	acme.ProviderHetzner: {
		DisplayName: "Hetzner",
		Required:    []string{"HETZNER_API_KEY"},
		Docs:        "https://go-acme.github.io/lego/dns/hetzner/",
		New:         func() (challenge.Provider, error) { return hetzner.NewDNSProvider() },
	},
	acme.ProviderVultr: {
		DisplayName: "Vultr",
		Required:    []string{"VULTR_API_KEY"},
		Docs:        "https://go-acme.github.io/lego/dns/vultr/",
		New:         func() (challenge.Provider, error) { return vultr.NewDNSProvider() },
	},
}

// detectionOrder is the one ordered list auto-detection walks, most popular
// first. TestDetectionOrder_CoversRegistryExactly pins it to the registry so a
// new provider cannot be forgotten here.
var detectionOrder = []acme.ProviderName{
	acme.ProviderCloudflare,
	acme.ProviderRoute53,
	acme.ProviderDigitalOcean,
	acme.ProviderHetzner,
	acme.ProviderVultr,
	acme.ProviderGoogleCloud,
	acme.ProviderNamecheap,
	acme.ProviderGoDaddy,
}
