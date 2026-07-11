# Kamal Proxy - A minimal HTTP proxy for zero-downtime deployments


## What it does

Kamal Proxy is a tiny HTTP proxy, designed to make it easy to coordinate
zero-downtime deployments. By running your web applications behind Kamal Proxy,
you can deploy changes to them without interrupting any of the traffic that's in
progress. No particular cooperation from an application is required for this to
work.

Kamal Proxy is designed to work as part of [Kamal](https://kamal-deploy.org/),
which provides a complete deployment experience including container packaging
and provisioning. However, Kamal Proxy could also be used standalone or as part
of other deployment tooling.


## A quick overview

To run an instance of the proxy, use the `kamal-proxy run` command. There's no
configuration file, but there are some options you can specify if the defaults
aren't right for your application.

For example, to run the proxy on a port other than 80 (the default) you could:

    kamal-proxy run --http-port 8080

Run `kamal-proxy help run` to see the full list of options.

To route traffic through the proxy to a web application, you `deploy` instances
of the application to the proxy. Deploying an instance makes it available to the
proxy, and replaces the instance it was using before (if any).

Use the format `hostname:port` when specifying the instance to deploy.

For example:

    kamal-proxy deploy service1 --target web-1:3000

This will instruct the proxy to register `web-1:3000` to receive traffic under
the service name `service1`. It will immediately begin running HTTP health
checks to ensure it's reachable and working and, as soon as those health checks
succeed, will start routing traffic to it.

If the instance fails to become healthy within a reasonable time, the `deploy`
command will stop the deployment and return a non-zero exit code, allowing
deployment scripts to handle the failure appropriately.

Each deployment takes over all the traffic from the previously deployed
instance. As soon as Kamal Proxy determines that the new instance is healthy,
it will route all new traffic to that instance.

The `deploy` command also waits for traffic to drain from the old instance before
returning. This means it's safe to remove the old instance as soon as `deploy`
returns successfully, without interrupting any in-flight requests.

Because traffic is only routed to a new instance once it's healthy, and traffic
is drained completely from old instances before they are removed, deployments
take place with zero downtime.

### Customizing the health check

By default, Kamal Proxy will test the health of each service by sending a `GET`
request to `/up`, once per second. A `200` response is considered healthy.

If you need to customize the health checks for your application, there are a
few `deploy` flags you can use. See the help for `--health-check-path`,
`--health-check-port`, `--health-check-timeout`, and `--health-check-interval`.

For example, to change the health check path to something other than `/up`, you
could:

    kamal-proxy deploy service1 --target web-1:3000 --health-check-path web/index.html

To configure health checks to run on a different port than your main service
(useful when your app exposes health endpoints on a dedicated port), you could:

    kamal-proxy deploy service1 --target web-1:3000 --health-check-port 8080

### Host-based routing

Host-based routing allows you to run multiple applications on the same server,
using a single instance of Kamal Proxy to route traffic to all of them.

When deploying an instance, you can specify a host that it should serve traffic
for:

    kamal-proxy deploy service1 --target web-1:3000 --host app1.example.com

When deployed in this way, the instance will only receive traffic for the
specified host. By deploying multiple instances, each with their own host, you
can run multiple applications on the same server without port conflicts.

Only one service at a time can route a specific host:

    kamal-proxy deploy service1 --target web-1:3000 --host app1.example.com
    kamal-proxy deploy service2 --target web-2:3000 --host app1.example.com # returns "Error: host is used by another service"
    kamal-proxy remove service1
    kamal-proxy deploy service2 --target web-2:3000 --host app1.example.com # succeeds


### Path-based routing

For applications that split their traffic to different services based on the
request path, you can use path-based routing to mount services under different
path prefixes.

For example, to send all the requests for paths begining with `/api` to web-1,
and the rest to web-2:

    kamal-proxy deploy service1 --target web-1:3000 --path-prefix=/api
    kamal-proxy deploy service2 --target web-2:3000

By default, the path prefix will be stripped from the request before it is
forwarded upstream. So in the example above, a request to `/api/users/123` will
be forwarded to `web-1` as `/users/123`. To instead forward the request with
the original path (including the prefix), specify `--strip-path-prefix=false`:

    kamal-proxy deploy service1 --target web-1:3000 --path-prefix=/api --strip-path-prefix=false


### Automatic TLS

Kamal Proxy can automatically obtain and renew TLS certificates for your
applications. To enable this, add the `--tls` flag when deploying an instance:

    kamal-proxy deploy service1 --target web-1:3000 --host app1.example.com --tls

Automatic TLS requires that hosts are specified (to ensure that certificates
are not maliciously requests for arbitrary hostnames).

Additionally, when using path-based routing, TLS options must be set on the
root path. Services deployed to other paths on the same host will use the same
TLS settings as those specified for the root path.


### Custom TLS certificate

When you obtained your TLS certificate manually, manage your own certificate authority,
or need to install Cloudflare origin certificate, you can manually specify path to
your certificate file and the corresponding private key:

    kamal-proxy deploy service1 --target web-1:3000 --host app1.example.com --tls --tls-certificate-path cert.pem --tls-private-key-path key.pem


### SAN Certificate Batching

When started with `--acme-email` (or the `ACME_EMAIL` environment variable),
Kamal Proxy batches multiple domains into a single SAN (Subject Alternative Name)
certificate. This dramatically reduces the number of certificates needed and helps
avoid Let's Encrypt rate limits.

Without `--acme-email`, Kamal Proxy falls back to issuing separate certificates
per service using the standard autocert flow.

**How it works:**

1. When services with TLS enabled are deployed, domains are queued for certificate provisioning
2. All pending domains (up to 100) are batched into a single certificate request
3. The resulting SAN certificate covers all domains, regardless of their root domain

**Example:**

```bash
kamal-proxy deploy app1 --target web-1:3000 --host app.example.com --tls
kamal-proxy deploy app2 --target web-2:3000 --host api.other.org --tls
kamal-proxy deploy app3 --target web-3:3000 --host mysite.net --tls
# → All three services share a single certificate with SANs:
#   app.example.com, api.other.org, mysite.net
```

**Rate limit impact:**

| Domains | Without batching | With SAN batching |
|---------|------------------|-------------------|
| 10      | 10 certificates  | 1 certificate     |
| 100     | 100 certificates | 1 certificate     |
| 1000    | 1000 certificates| 10 certificates   |

**Benefits:**

- **Dramatic reduction**: Up to 100 domains per certificate
- **Rate limit friendly**: 1000 domains = 10 certs instead of 1000
- **Any domains**: Works across different root domains
- **Minimal configuration**: Set `--acme-email` once, then deploy with `--tls` as usual

**Configuration options:**

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--acme-email` | `ACME_EMAIL` | (required for SAN batching) | Contact email for Let's Encrypt |
| `--acme-directory` | `ACME_DIRECTORY` | Let's Encrypt production | ACME directory URL |

**Using Let's Encrypt staging environment:**

For testing, use the staging environment to avoid rate limits:

```bash
kamal-proxy run --acme-email admin@example.com \
  --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory
```


### Dynamic domains with automatic TLS

SaaS apps that host many customer domains usually only know the full domain
list at runtime, in their own database. With a *domain source*, Kamal Proxy
learns that list from the app itself and fully manages certificates for it:
proactive throttled issuance, background renewal (ARI), per-domain failure
quarantine, and eviction when a domain is removed. A domain added in the app
serves HTTPS within minutes — no deploys, config edits, or restarts.

Requires running with `--acme-email`. Enable per service at deploy time:

```bash
kamal-proxy deploy service1 --target web-1:3000 --tls \
  --tls-domains-source /api/v1/domains
```

The source is polled every 5 minutes (`--tls-domains-interval` to change,
minimum 10s), resolved against a healthy target of the service — or use an
absolute `http(s)://` URL. `ETag`/`If-None-Match` are honored. The endpoint
must return:

```json
{"domains": ["customer1.com", "www.customer2.org"]}
```

Wildcard entries (`*.example.com`) are skipped (they need DNS-01), invalid
hostnames are skipped, and payloads over 1MB or 10,000 entries are rejected.
Set `KAMAL_PROXY_DOMAINS_TOKEN` to send `Authorization: Bearer <token>` with
each poll.

A service with a domain source must be the catch-all: deploy it without
`--host` (dynamic domains route through the host-less binding, so `--tls` no
longer requires one). The fetched list is a hard allowlist — TLS handshakes
for unknown hostnames are refused without touching Let's Encrypt.

**Push refresh (optional).** To pick up new domains faster than the poll
interval, set `KAMAL_PROXY_REFRESH_TOKEN` on the proxy and have the app nudge
it after changing domains:

```bash
curl -X POST -H "Authorization: Bearer $KAMAL_PROXY_REFRESH_TOKEN" \
  http://proxy-host/.kamal-proxy/domains/refresh
```

The nudge carries no data — it just triggers an immediate re-poll (202). It
answers 401 for bad tokens, 404 when unconfigured, and 429 more than once per
10s.

**Certificates and Let's Encrypt limits.** Dynamic domains are issued
per-domain by default, throttled well under Let's Encrypt's account limits
(burst of 20 orders, then one per 40s, max 3 in flight). Before a domain's
first order, the proxy probes `http://<domain>/.kamal-proxy/preflight/<nonce>`
to verify DNS actually routes here — unreachable domains are quarantined
(5m, then 15m → 1h → 4h → 24h backoff) without burning an order. Failing
domains quarantine alone; the rest of a batch is retried once. Renewals reuse
the exact same identifier set (exempt from most rate limits) and pass ARI
`replaces` where supported.

`--tls-domains-batch-size` (max 25) opts into stable SAN batching for dynamic
domains: batches fill append-only, and membership only changes at renewal
boundaries. Note that batching publishes all tenants of a batch together in
certificate-transparency logs, and one dead domain can hold up its batch —
per-domain (the default) is recommended.

The last fetched list and quarantine state persist in
`dynamic-domains.state`, so certificates keep serving after a restart even if
the app is down.

**Inspecting:**

```bash
kamal-proxy domains list      # every dynamic domain, cert + quarantine status
kamal-proxy domains stats     # counters: domains, certified, queued, quarantined
kamal-proxy domains refresh   # trigger an immediate re-poll of all sources
```


### Wildcard Certificates (DNS-01 Challenge)

For deployments with many subdomains, you can use wildcard certificates to avoid
Let's Encrypt rate limits. Wildcard certificates require DNS-01 challenge, which
needs access to your DNS provider's API.

**Supported DNS Providers:**

| Provider | Environment Variables |
|----------|----------------------|
| Cloudflare | `CF_API_TOKEN` or (`CF_API_KEY` + `CF_API_EMAIL`) |
| AWS Route53 | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| DigitalOcean | `DO_AUTH_TOKEN` |
| Google Cloud DNS | `GCE_PROJECT` + `GOOGLE_APPLICATION_CREDENTIALS` |
| Namecheap | `NAMECHEAP_API_USER` + `NAMECHEAP_API_KEY` |
| GoDaddy | `GODADDY_API_KEY` + `GODADDY_API_SECRET` |
| Hetzner | `HETZNER_API_KEY` |
| Vultr | `VULTR_API_KEY` |

**Enabling wildcard certificates:**

1. Set DNS provider credentials as environment variables
2. Start kamal-proxy with ACME email configured:

```bash
export CF_API_TOKEN=your-cloudflare-token
kamal-proxy run --acme-email admin@example.com --acme-dns-provider cloudflare
```

3. Deploy services as normal - wildcards are provisioned automatically:

```bash
kamal-proxy deploy app --target web-1:3000 --host app.example.com --tls
kamal-proxy deploy api --target web-2:3000 --host api.example.com --tls
# → Both services share a *.example.com wildcard certificate
```

**How certificate grouping works:**

When you deploy services with TLS enabled, kamal-proxy automatically:

1. Groups domains by their root domain (e.g., `app.example.com` and `api.example.com` → `example.com`)
2. When 2+ subdomains share a root domain, provisions a wildcard certificate (`*.example.com`)
3. Shares the wildcard certificate across all matching services
4. Falls back to individual certificates for unrelated domains

This dramatically reduces the number of certificates needed and avoids Let's Encrypt
rate limits (50 certificates per registered domain per week).

**ACME configuration options:**

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--acme-email` | `ACME_EMAIL` | (required) | Contact email for Let's Encrypt |
| `--acme-dns-provider` | `ACME_DNS_PROVIDER` | `auto` | DNS provider (cloudflare, route53, digitalocean, gcloud, namecheap, godaddy, hetzner, vultr, auto) |
| `--acme-directory` | `ACME_DIRECTORY` | Let's Encrypt production | ACME directory URL |
| `--acme-prefer-wildcard` | `ACME_PREFER_WILDCARD` | `true` | Prefer wildcard certificates when DNS provider available |
| `--acme-http-fallback` | `ACME_HTTP_FALLBACK` | `true` | Fall back to HTTP-01 challenge if DNS-01 fails |

**Using Let's Encrypt staging environment:**

For testing, use the staging environment to avoid rate limits:

```bash
kamal-proxy run --acme-email admin@example.com --acme-dns-provider cloudflare \
  --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory
```


## Specifying `run` options with environment variables

In some environments, like when running a Docker container, it can be convenient
to specify `run` options using environment variables. This avoids having to
update the `CMD` in the Dockerfile to change the options. To support this,
`kamal-proxy run` will read each of its options from environment variables if they
are set. For example, setting the HTTP port can be done with either:

    kamal-proxy run --http-port 8080

or:

    HTTP_PORT=8080 kamal-proxy run

If any of the environment variables conflict with something else in your
environment, you can prefix them with `KAMAL_PROXY_` to disambiguate them. For
example:

    KAMAL_PROXY_HTTP_PORT=8080 kamal-proxy run


## Configuring with Kamal

When using kamal-proxy with [Kamal](https://kamal-deploy.org/), you can configure
the proxy through your `deploy.yml` file.

### Enabling Wildcard Certificates in Kamal

To use wildcard certificates with Kamal, add the DNS provider credentials and
ACME configuration to your proxy settings:

```yaml
# deploy.yml

proxy:
  ssl: true
  host: app.example.com
  # Additional hosts will share the wildcard certificate
  # hosts:
  #   - api.example.com
  #   - admin.example.com

# Pass environment variables to the kamal-proxy container
env:
  clear:
    # ACME configuration (required for wildcard certs)
    ACME_EMAIL: admin@example.com
    ACME_DNS_PROVIDER: cloudflare

  secret:
    # DNS provider credentials (from .kamal/secrets)
    - CF_API_TOKEN
```

### Setting up secrets

Create or update `.kamal/secrets` with your DNS provider credentials:

```bash
# .kamal/secrets
CF_API_TOKEN=your-cloudflare-api-token
```

For AWS Route53:
```bash
# .kamal/secrets
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
```

### Complete example with multiple services

```yaml
# deploy.yml
service: myapp

servers:
  web:
    hosts:
      - 192.168.1.1
    proxy:
      ssl: true
      host: app.example.com

  api:
    hosts:
      - 192.168.1.1
    proxy:
      ssl: true
      host: api.example.com

env:
  clear:
    ACME_EMAIL: admin@example.com
    ACME_DNS_PROVIDER: cloudflare
    ACME_PREFER_WILDCARD: true

  secret:
    - CF_API_TOKEN
```

With this configuration:
- Both `app.example.com` and `api.example.com` will share a `*.example.com` wildcard certificate
- Certificate is automatically provisioned and renewed
- No rate limiting issues with Let's Encrypt

### Troubleshooting

**Certificate not provisioning:**
- Check DNS provider credentials are correct
- Ensure the DNS API can create TXT records in your zone
- Check kamal-proxy logs: `docker logs kamal-proxy`

**Using staging environment for testing:**
```yaml
env:
  clear:
    ACME_EMAIL: admin@example.com
    ACME_DNS_PROVIDER: cloudflare
    ACME_DIRECTORY: https://acme-staging-v02.api.letsencrypt.org/directory
```


## Building

To build Kamal Proxy locally, if you have a working Go environment you can:

    make

Alternatively, build as a Docker container:

    make docker


## Trying it out

See the [example](./example) folder for a Docker Compose setup that you can use
to try out the proxy commands.
