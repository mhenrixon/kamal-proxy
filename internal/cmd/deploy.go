package cmd

import (
	"fmt"
	"net/rpc"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type deployCommand struct {
	cmd                 *cobra.Command
	args                server.DeployArgs
	tlsStaging          bool
	pathTimeouts        map[string]string
	pathRequestTimeouts map[string]string
	basicAuth           string
	requestHeaderRules  server.HeaderRuleFlags
	responseHeaderRules server.HeaderRuleFlags
	redirects           []string
	rewrites            []string
}

func newDeployCommand() *deployCommand {
	deployCommand := &deployCommand{}
	deployCommand.cmd = &cobra.Command{
		Use:       "deploy <service>",
		Short:     "Deploy a target host",
		PreRunE:   deployCommand.preRun,
		RunE:      deployCommand.run,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"service"},
	}

	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.TargetURLs, "target", []string{}, "Target host(s) to deploy, as <host>[:<port>][;weight=<n>]. A weight is that target's share of requests relative to its healthy peers (default 1, max 1000), so --target=a --target='b;weight=5' sends b five times the traffic of a. Quote the value: the shell eats an unquoted semicolon")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ReaderURLs, "read-target", []string{}, "Read-only target host(s) to deploy. Takes the same ;weight=<n> suffix as --target, applied across the read pool only")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.Hosts, "host", []string{}, "Host(s) to serve this target on (empty for wildcard)")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.PathPrefixes, "path-prefix", []string{}, "Deploy the service below the specified path(s)")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.ServiceOptions.StripPrefix, "strip-path-prefix", true, "With --path-prefix, strip prefix from request before forwarding")

	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.ServiceOptions.TLSEnabled, "tls", false, "Configure TLS for this target (requires a non-empty host)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.TLSOnDemandURL, "tls-on-demand-url", "", "Will make an HTTP request to the given URL, asking whether a host is allowed to have a certificate issued")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.tlsStaging, "tls-staging", false, "Use Let's Encrypt staging environment for certificate provisioning")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.TLSCertificatePath, "tls-certificate-path", "", "Configure custom TLS certificate path (PEM format)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.TLSPrivateKeyPath, "tls-private-key-path", "", "Configure custom TLS private key path (PEM format)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.TLSClientCACertificatePath, "tls-client-ca-path", "", "Require client certificates signed by this CA bundle (mTLS; PEM format)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.ACMECachePath, "tls-acme-cache-path", globalConfig.CertificatePath(), "Location to store ACME assets")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.ServiceOptions.TLSRedirect, "tls-redirect", true, "Redirect HTTP traffic to HTTPS")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.TLSDomainsSource, "tls-domains-source", "", "Fetch additional TLS domains from this endpoint (path resolved against the service, or absolute URL)")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.TLSDomainsInterval, "tls-domains-interval", 0, "Interval between domain source polls (default 5m)")
	deployCommand.cmd.Flags().IntVar(&deployCommand.args.ServiceOptions.TLSDomainsBatchSize, "tls-domains-batch-size", 0, "Dynamic domains to batch per certificate (default 1, max 25)")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.SleepAfter, "sleep-after", 0, "Stop this service's target containers after this long with no traffic, and start them again on the next request (default 0, never). Requires the proxy to run with --docker-socket. Health checks and the proxy's own TLS probes are not traffic and never wake a sleeping service")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.WakeTimeout, "wake-timeout", server.DefaultWakeTimeout, "Maximum time a request waits for a sleeping service's containers to start and pass a health check before failing with 503")
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.args.ServiceOptions.SleepContainers, "sleep-container", nil, "Container to stop and start for --sleep-after, replacing what the proxy infers from the target address. Needed when a target names a network alias rather than a container (may be specified multiple times)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.CanonicalHost, "canonical-host", "", "Redirect all requests to this host (e.g., force root or www)")

	// StringArray rather than StringSlice: a pattern or a replacement may
	// contain commas, which StringSlice would split into separate rules.
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.redirects, "redirect", nil, "Answer matching requests with a redirect, as '<pattern>=<replacement>[;status=<code>]' (e.g. '/blog/(.*)=/news/$1', default status 301, also 302/303/307/308). The pattern is a regular expression matched against the whole request path; the replacement is a path on this host or a full URL, and keeps the request's query unless it carries one of its own. Rules are tried in order, first match wins (may be specified multiple times)")
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.rewrites, "rewrite", nil, "Change the path forwarded to the target without telling the client, as '<pattern>=<replacement>' (e.g. '/[^.]*=/index.html' to serve an SPA's own routes). Same matching as --redirect; the replacement must be a path (may be specified multiple times)")

	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.DeploymentOptions.DeployTimeout, "deploy-timeout", server.DefaultDeployTimeout, "Maximum time to wait for the new target to become healthy")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.DeploymentOptions.DrainTimeout, "drain-timeout", server.DefaultDrainTimeout, "Maximum time to allow existing connections to drain before removing old target")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.DeploymentOptions.Force, "force", false, "Skip health checks and force deployment")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.TargetOptions.HealthCheckConfig.Interval, "health-check-interval", server.DefaultHealthCheckInterval, "Interval between health checks")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.TargetOptions.HealthCheckConfig.Timeout, "health-check-timeout", server.DefaultHealthCheckTimeout, "Time each health check must complete in")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.TargetOptions.HealthCheckConfig.Path, "health-check-path", server.DefaultHealthCheckPath, "Path to check for health")
	deployCommand.cmd.Flags().IntVar(&deployCommand.args.TargetOptions.HealthCheckConfig.Port, "health-check-port", server.DefaultHealthCheckPort, "Port to check for health (default matches target port)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.TargetOptions.HealthCheckConfig.Host, "health-check-host", "", "Host header to send with health check requests")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.WriterAffinityTimeout, "writer-affinity-timeout", server.DefaultWriterAffinityTimeout, "Time after a write before read requests will be routed to readers")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.ServiceOptions.ReadTargetsAcceptWebsockets, "read-target-websockets", false, "Route WebSocket traffic to read targets, when available")

	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.TargetOptions.ResponseTimeout, "target-timeout", server.DefaultTargetTimeout, "Maximum time to wait for the target server to respond when serving requests")
	deployCommand.cmd.Flags().StringToStringVar(&deployCommand.pathTimeouts, "path-timeout", nil, "Override --target-timeout below a path prefix, as <prefix>=<duration> (0 for no timeout; may be specified multiple times)")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.TargetOptions.RequestTimeout, "request-timeout", 0, "Maximum time a whole request may take, including streaming the response body (default 0, no limit; WebSocket and event-stream responses are exempt)")
	deployCommand.cmd.Flags().StringToStringVar(&deployCommand.pathRequestTimeouts, "path-request-timeout", nil, "Override --request-timeout below a path prefix, as <prefix>=<duration> (0 for no limit; may be specified multiple times)")

	deployCommand.cmd.Flags().IntVar(&deployCommand.args.TargetOptions.MaxConnsPerHost, "target-max-conns", 0, "Max simultaneous connections to each target, including idle ones (default 0, unlimited). Requests over the cap queue rather than failing, and streaming responses hold a connection until their body closes, so pair a low limit with --request-timeout. Applies per connection pool, and each --path-timeout adds another pool")
	deployCommand.cmd.Flags().IntVar(&deployCommand.args.TargetOptions.MaxIdleConnsPerHost, "target-max-idle-conns", 0, "Max idle connections kept open per target (default 100). Applies per connection pool, and each --path-timeout adds another pool")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.TargetOptions.IdleConnTimeout, "target-idle-conn-timeout", 0, "How long an idle connection to a target is kept before closing (default 90s; set below the target's own keep-alive timeout)")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.TargetOptions.DialTimeout, "target-dial-timeout", 0, "Maximum time to establish a connection to a target (default 30s); health checks use their own client and are unaffected")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.TargetOptions.DisableKeepAlives, "target-disable-keep-alives", false, "Close each connection to the target after a single request")

	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.TargetTryDuration, "target-try-duration", 0, "How long to keep trying to place a request on a healthy target before giving up (default 0, single attempt; only idempotent requests without a body are re-sent to another target)")
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.TargetTryInterval, "target-try-interval", 0, "Pause between attempts while waiting for a healthy target (default 250ms; requires --target-try-duration)")

	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.ServiceOptions.SessionAffinity, "session-affinity", false, "Keep each client on the target that first served it, for apps holding session state in the instance (default false, every request is rotated). The client carries an opaque HttpOnly cookie naming the target; when that target leaves the pool the next request falls through to another one and is re-pinned. Reads served by a --read-target are not pinned")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.SessionAffinityCookieName, "session-affinity-cookie", "", fmt.Sprintf("Name of the --session-affinity pin cookie (default %s)", server.DefaultSessionAffinityCookieName))

	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.TargetOptions.BufferRequests, "buffer-requests", false, "Buffer requests before forwarding to target")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.TargetOptions.BufferResponses, "buffer-responses", false, "Buffer responses before forwarding to client")
	deployCommand.cmd.Flags().Int64Var(&deployCommand.args.TargetOptions.MaxMemoryBufferSize, "buffer-memory", server.DefaultMaxMemoryBufferSize, "Max size of memory buffer")
	deployCommand.cmd.Flags().Int64Var(&deployCommand.args.TargetOptions.MaxRequestBodySize, "max-request-body", server.DefaultMaxRequestBodySize, "Max size of request body when buffering (default of 0 means unlimited)")
	deployCommand.cmd.Flags().Int64Var(&deployCommand.args.TargetOptions.MaxResponseBodySize, "max-response-body", server.DefaultMaxResponseBodySize, "Max size of response body when buffering (default of 0 means unlimited)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.ErrorPagePath, "error-pages", "", "Path to custom error pages")
	deployCommand.cmd.Flags().IntSliceVar(&deployCommand.args.ServiceOptions.InterceptErrorStatuses, "intercept-errors", nil, "Replace these response statuses from the target with the proxy's error pages, as 4xx or 5xx codes (e.g. 502,503,504; default none)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.basicAuth, "basic-auth", "", "Require HTTP Basic credentials on every request to this service, as <username>:<password>. The health check path stays open. Use with --tls, or terminate TLS in front of the proxy -- Basic credentials are replayable and are sent on every request")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.AllowIPs, "allow-ip", nil, "Serve this service only to these addresses or CIDR ranges (e.g. 10.0.0.0/8,203.0.113.7; default empty, serve everyone). Matches the connecting address, so list IPv6 ranges too if clients reach the proxy over IPv6. The health check path stays open")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.TrustedProxies, "trusted-proxy", nil, "Addresses or CIDR ranges of proxies in front of this one. Only when the connecting address is one of these are --allow-ip and --rate-limit matched against the forwarded chain instead. List every hop, not just the one that connects to kamal-proxy")
	deployCommand.cmd.Flags().Float64Var(&deployCommand.args.ServiceOptions.RateLimit, "rate-limit", 0, "Max requests per second from a single client (default 0, no limit). Requests over the limit get a 429. Counts the connecting address unless --trusted-proxy is set; IPv6 clients are counted per /64, since a client can pick any address in its own. The health check path stays open")
	deployCommand.cmd.Flags().IntVar(&deployCommand.args.ServiceOptions.RateLimitBurst, "rate-limit-burst", 0, "How many requests a client may make back to back before --rate-limit applies (default 0, meaning the rate rounded up)")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.RateLimitExempt, "rate-limit-exempt", nil, "Addresses or CIDR ranges that --rate-limit does not apply to (e.g. 10.0.0.0/8 for monitoring; default empty)")

	// StringArray rather than StringSlice: a header value may contain commas, as
	// "Access-Control-Allow-Methods: GET, POST" and "Cache-Control: no-store,
	// max-age=0" do, and StringSlice would split those into separate rules.
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.requestHeaderRules.Set, "set-request-header", nil, "Header to set on requests before forwarding them, as '<name>: <value>', replacing what the client sent (may be specified multiple times)")
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.requestHeaderRules.Add, "add-request-header", nil, "Header to append to requests before forwarding them, as '<name>: <value>', keeping what the client sent (may be specified multiple times)")
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.requestHeaderRules.Remove, "remove-request-header", nil, "Header to strip from requests before forwarding them (may be specified multiple times)")
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.responseHeaderRules.Set, "set-response-header", nil, "Header to set on responses from the target, as '<name>: <value>', replacing what the target sent. Applies to responses the target produced; error pages, redirects and auth or rate limit rejections come from the proxy and are unaffected (may be specified multiple times)")
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.responseHeaderRules.Add, "add-response-header", nil, "Header to append to responses from the target, as '<name>: <value>', keeping what the target sent (may be specified multiple times)")
	deployCommand.cmd.Flags().StringArrayVar(&deployCommand.responseHeaderRules.Remove, "remove-response-header", nil, "Header to strip from responses from the target (may be specified multiple times)")

	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.Compression.Encodings, "compress", nil, "Content encoding(s) to offer clients that accept them, most preferred first, as gzip, br and/or zstd (e.g. zstd,br,gzip; default empty, no compression). Responses the target already encoded, event streams, and media types that do not shrink are passed through")
	deployCommand.cmd.Flags().Int64Var(&deployCommand.args.ServiceOptions.Compression.MinLength, "compress-min-length", 0, fmt.Sprintf("Skip --compress for responses smaller than this many bytes (default %d; set 1 to compress everything)", server.DefaultCompressionMinLength))
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.Compression.ContentTypes, "compress-content-type", nil, "Replace the built-in list of compressible media types for --compress, as exact types or type wildcards (e.g. text/*,application/json)")

	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.ServiceOptions.Cache.Enabled, "cache", false, "Store responses this service's target marks 'public' with an s-maxage or max-age, and answer later requests from them. Nothing is stored without that explicit marking, and a response carrying Set-Cookie is refused unless --cache-allow-set-cookie. Where the entries live is set on the proxy with --cache-store")
	deployCommand.cmd.Flags().Int64Var(&deployCommand.args.ServiceOptions.Cache.MaxBodySize, "cache-max-body", 0, fmt.Sprintf("Largest response body --cache will store, in bytes (default %d). Bigger responses still reach the client, they are just not kept", server.DefaultCacheMaxBodySize))
	deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.Cache.MaxTTL, "cache-max-ttl", 0, "Cap on the lifetime the target asks for with s-maxage or max-age (default 0, no cap), so one mistaken directive cannot pin content until the next deploy")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.Cache.VaryHeaders, "cache-vary-header", nil, "Request header(s) added to the --cache key for EVERY response this service stores, whether or not the target names them in Vary. Two uses: an app that serves different content per header without saying so, and lifting the built-in refusal on a header that differs for every client such as Cookie or User-Agent. Headers the target DOES name in Vary are keyed automatically, per URL, and need no entry here -- naming one moves it into the key for every path in the service, which is usually not what you want")
	deployCommand.cmd.Flags().IntVar(&deployCommand.args.ServiceOptions.Cache.MaxVariants, "cache-max-variants", 0, fmt.Sprintf("How many representations one URL may hold when the target negotiates with Vary (default %d; negative to switch automatic variants off and refuse a varying response outright). Over the limit a response still reaches the client, it is just not stored -- watch cache_refusals_total{reason=\"variant_limit\"}", server.DefaultCacheMaxVariants))
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.Cache.VaryCookies, "cache-vary-cookie", nil, "Cookie name(s) the --cache key is computed over, for apps that serve different content per cookie without saying so in Vary")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.ServiceOptions.Cache.AllowSetCookie, "cache-allow-set-cookie", false, "Allow --cache to store responses carrying Set-Cookie. Off by default, because a shared cache replaying one client's cookie to the next is the worst thing it could do")

	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.TargetOptions.LogRequestHeaders, "log-request-header", nil, "Additional request header to log (may be specified multiple times)")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.TargetOptions.LogResponseHeaders, "log-response-header", nil, "Additional response header to log (may be specified multiple times)")
	deployCommand.cmd.Flags().StringSliceVar(&deployCommand.args.ServiceOptions.ExcludeMetricsPaths, "exclude-metrics-path", nil, "Request path(s) to exclude from Prometheus metrics (may be specified multiple times)")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.TargetOptions.ForwardHeaders, "forward-headers", false, "Forward X-Forwarded headers to target (default false if TLS enabled; otherwise true)")
	deployCommand.cmd.Flags().StringVar(&deployCommand.args.ServiceOptions.ClientIPHeader, "client-ip-header", "", "Request header containing the original client IP; used to populate X-Forwarded-For when present")
	deployCommand.cmd.Flags().BoolVar(&deployCommand.args.TargetOptions.ScopeCookiePaths, "scope-cookie-paths", false, "Scope cookie paths to match path prefix")

	deployCommand.cmd.MarkFlagRequired("target")
	deployCommand.cmd.MarkFlagsRequiredTogether("tls-certificate-path", "tls-private-key-path")

	return deployCommand
}

func (c *deployCommand) run(cmd *cobra.Command, args []string) error {
	c.args.Service = args[0]

	if c.tlsStaging {
		c.args.ServiceOptions.ACMEDirectory = server.ACMEStagingDirectoryURL
	}

	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response bool
		return client.Call("kamal-proxy.Deploy", c.args, &response)
	})
}

func (c *deployCommand) preRun(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("max-request-body") && !cmd.Flags().Changed("buffer-requests") {
		return fmt.Errorf("max-request-body can only be set when request buffering is enabled")
	}

	if cmd.Flags().Changed("max-response-body") && !cmd.Flags().Changed("buffer-responses") {
		return fmt.Errorf("max-response-body can only be set when response buffering is enabled")
	}

	if !cmd.Flags().Changed("forward-headers") {
		c.args.TargetOptions.ForwardHeaders = !c.args.ServiceOptions.TLSEnabled
	}

	var err error
	c.args.TargetOptions.PathResponseTimeouts, err = parsePathTimeouts("path-timeout", c.pathTimeouts)
	if err != nil {
		return err
	}

	c.args.TargetOptions.PathRequestTimeouts, err = parsePathTimeouts("path-request-timeout", c.pathRequestTimeouts)
	if err != nil {
		return err
	}

	if c.basicAuth != "" {
		username, password, err := parseBasicAuthFlag(c.basicAuth)
		if err != nil {
			return err
		}

		// Hash here, so the plaintext credential never crosses the RPC socket
		// and never reaches the state file.
		c.args.ServiceOptions.BasicAuth, err = server.EncodeBasicAuthCredential(username, password)
		if err != nil {
			return err
		}
	}

	c.args.TargetOptions.RequestHeaderRules, err = server.NewRequestHeaderRules(c.requestHeaderRules)
	if err != nil {
		return err
	}

	c.args.TargetOptions.ResponseHeaderRules, err = server.NewResponseHeaderRules(c.responseHeaderRules)
	if err != nil {
		return err
	}

	c.args.ServiceOptions.Redirects, err = server.NewRedirectRules(c.redirects)
	if err != nil {
		return err
	}

	c.args.ServiceOptions.Rewrites, err = server.NewRewriteRules(c.rewrites)
	if err != nil {
		return err
	}

	if err := c.args.TargetOptions.Validate(); err != nil {
		return err
	}

	if err := c.args.ServiceOptions.Validate(); err != nil {
		return err
	}

	return nil
}

// parseBasicAuthFlag splits a <username>:<password> flag value. It cuts at the
// first colon, matching how net/http decodes the credentials a client sends:
// passwords may contain colons, usernames may not.
func parseBasicAuthFlag(value string) (string, string, error) {
	username, password, found := strings.Cut(value, ":")
	if !found {
		return "", "", fmt.Errorf("%w: basic-auth must be given as <username>:<password>", server.ErrServiceOptionsInvalid)
	}
	if username == "" || password == "" {
		return "", "", fmt.Errorf("%w: basic-auth needs both a username and a password", server.ErrServiceOptionsInvalid)
	}

	return username, password, nil
}

// parsePathTimeouts converts the <prefix>=<duration> flag pairs into the
// server's normalized, longest-prefix-first form. The map's iteration order is
// random, so normalizing here is what makes the deployed order deterministic.
func parsePathTimeouts(flagName string, values map[string]string) ([]server.PathTimeout, error) {
	if len(values) == 0 {
		return nil, nil
	}

	pathTimeouts := make([]server.PathTimeout, 0, len(values))
	for pathPrefix, value := range values {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout < 0 {
			return nil, fmt.Errorf("invalid --%s duration for '%s': %s", flagName, pathPrefix, value)
		}

		pathTimeouts = append(pathTimeouts, server.PathTimeout{PathPrefix: pathPrefix, Timeout: timeout})
	}

	return server.NormalizePathTimeouts(pathTimeouts), nil
}
