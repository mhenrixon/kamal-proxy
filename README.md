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

### Monitoring the proxy itself

The health checks above tell the proxy whether your *app* is up. To let an
external uptime monitor tell whether the *proxy* is up, there is a liveness
endpoint answered by the proxy itself:

    curl http://your-server/.kamal-proxy/ping
    # → 200 OK

Point your uptime monitor at that URL rather than at one of your apps, and a
page tells you the proxy is gone instead of blaming whichever service you
happened to pick as the canary.

Things worth knowing:

* **It answers before anything is deployed.** Liveness means this process is
  serving, so a freshly booted proxy with zero services answers `200` on plain
  HTTP — you do not need TLS, a host, or a deployment for it to work.
* **It answers on every host the proxy serves**, over HTTP and HTTPS alike, and
  is never forwarded upstream. `/.kamal-proxy/` is reserved by the proxy, so an
  app cannot serve its own page there.
* **It is not authenticated and not rate limited.** It reveals only that a
  kamal-proxy is running on the port, which anyone connecting to the port can
  already tell. If you would rather it not be reachable from the internet,
  block the path at your edge.
* **It is not in the access log** and carries `Cache-Control: no-store`, so
  probing once a second costs you neither log volume nor a stale cached `200`.
* **There is no matching readiness endpoint.** The proxy restores its routing
  state before it opens a listener, and closes its listeners when draining, so
  a readiness probe here could only ever say `200`. Whether the port accepts a
  connection at all is the real signal.

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


### Excluding paths from metrics

When metrics are enabled (with `--metrics-port`), every request handled by
the proxy is recorded in the Prometheus output. High-volume traffic from
upstream load balancers or uptime monitors hitting health endpoints can
both inflate the metrics pipeline and dominate aggregate measures like
request rate, latency percentiles, and error rates, making the resulting
metrics a poor reflection of real user traffic.

To exclude one or more paths from the metrics for a service, use
`--exclude-metrics-path` when deploying. The flag may be repeated, and
matches are exact:

    kamal-proxy deploy service1 --target web-1:3000 --exclude-metrics-path /up --exclude-metrics-path /healthz

Excluded requests are still logged; only the Prometheus counters and
in-flight gauge are skipped.

Paths are specified as the upstream receives them. Services deployed using
stripped path prefixes should specify their excluded paths in the un-prefixed
form.


### Choosing a log format

Logs are written as JSON by default. To write logfmt instead, start the proxy
with `--log-format` (or the `LOG_FORMAT` environment variable):

    kamal-proxy run --log-format text

Accepted values are `json` and `text`; `logfmt` is accepted as a synonym for
`text`. The setting covers the whole process — the per-request access log and
the proxy's own startup, certificate and shutdown messages all go through the
same handler, so a log pipeline never has to parse two shapes at once.


### Correlating logs with distributed traces

If your clients or an upstream load balancer already send a W3C
[`traceparent`](https://www.w3.org/TR/trace-context/) header, the proxy reads it
and adds `trace_id`, `span_id` and `trace_flags` to that request's access log
line, so proxy logs join the trace your application is already recording. The
header itself is forwarded byte for byte.

This is on by default. Control it with `--trace-context` (or the
`TRACE_CONTEXT` environment variable):

    kamal-proxy run --trace-context generate

| Value | Behaviour |
| --- | --- |
| `off` | The header is neither read nor logged. It still reaches the target, like any other header. |
| `propagate` (default) | A valid incoming `traceparent` is logged and forwarded unchanged. A missing or malformed one is left exactly as it arrived. |
| `generate` | As `propagate`, and a request arriving without a valid `traceparent` gets a newly minted one, so every request downstream carries a trace id that the access log also names. |

The trace attributes appear only on requests that actually carry a trace, so
enabling this changes nothing about the log lines of a deployment that does not
trace.

`span_id` is the **caller's** span — the one your application will parent its
own spans to. The proxy deliberately does not mint a span of its own: it exports
no spans to any backend, so a span id invented here would leave your application
parented to a span that no tracing backend has ever seen.

Traces minted by `generate` are marked sampled (`trace_flags` `01`). The
alternative would be worse than not minting one at all — an application that
would otherwise have made its own sampling decision honours the parent's
instead, so an unsampled parent silently switches its tracing off. Use
`generate` when you want the proxy to be the start of the trace, and leave it at
`propagate` when your application already decides what to sample.

Per the spec, a request whose `traceparent` is malformed has its `tracestate`
dropped when `generate` replaces the header — that `tracestate` describes the
trace that was just discarded.


### Password-protecting a service

To put a service behind an HTTP Basic password prompt, deploy it with
`--basic-auth`:

    kamal-proxy deploy service1 --target web-1:3000 --tls --host app.example.com --basic-auth admin:s3cr3t

Requests without valid credentials get a `401` and a browser password prompt.
The password is hashed by the CLI before it is sent to the proxy, so neither
the RPC socket nor the saved state file ever sees the plaintext.

Things worth knowing:

* **Use it with TLS.** Basic credentials are replayable and are re-sent on
  every request. On a service deployed with `--tls`, plaintext requests are
  redirected to HTTPS *before* any challenge is issued, so the password is
  never solicited in the clear. If you turn that redirect off with
  `--tls-redirect=false`, or deploy without `--tls` at all, the proxy logs a
  warning and challenges over plaintext — only do that when TLS is terminated
  in front of the proxy.
* **The health check path stays open.** `GET` and `HEAD` on the configured
  `--health-check-path` are served without credentials, so downstream load
  balancers can still see the service drain during a deploy. Deploying with
  both `--basic-auth` and a health check path of `/` is rejected, since that
  would leave the service's index page public.
* **The credential is removed before forwarding.** Your application never sees
  the proxy's `Authorization` header, so it cannot be logged by
  `--log-request-header authorization` or read by the upstream.
* **Rollout targets inherit it.** `kamal-proxy rollout deploy` reuses the
  service's stored options, so rollout traffic stays protected.
* **Redeploying without the flag removes protection.** The credential is not
  sticky; a deploy that omits `--basic-auth` leaves the service open.
* **Rolling the proxy image back removes protection silently.** A binary older
  than this feature ignores the stored credential and the next state save drops
  it. Redeploy with `--basic-auth` after any proxy rollback.
* **The password reaches the deploy host's process table.** It is an ordinary
  command-line argument, so it is visible to `ps` and to anything that logs the
  command.
* **A per-path prefix is routing, not a security boundary.** You can protect
  part of a site by deploying it as its own `--path-prefix` service with its own
  credential, but prefix matching does not normalize paths — give the protected
  prefix a target that does not also serve the same content under an
  unprotected root.

If you use `--error-pages`, add a `401.html` to that directory; otherwise the
challenge falls back to the proxy's built-in plain response.


### Restricting a service by client address

To serve a service only to certain networks, deploy it with `--allow-ip`:

    kamal-proxy deploy service1 --target web-1:3000 --allow-ip 10.0.0.0/8,203.0.113.7

Requests from anywhere else get a `403`. The flag takes addresses or CIDR
ranges, and may be repeated or comma-separated. Metrics have their own list:

    kamal-proxy run --metrics-port 9090 --metrics-allow-ip 10.0.0.0/8

Things worth knowing:

* **It matches the address that connected**, not any header. `X-Forwarded-For`
  and friends are written by the client, so honouring them by default would
  make the list decorative — anyone could send `X-Forwarded-For: 10.0.0.1`.
* **Behind a load balancer or CDN, say so with `--trusted-proxy`.** Only when
  the connecting address is inside one of those ranges is the forwarded chain
  consulted, and then the client is the nearest address in the chain that none
  of your proxies wrote. **List every hop, not just the one that connects to
  kamal-proxy** — behind a CDN in front of a load balancer, list both, or the
  CDN's edge address becomes the one matched against `--allow-ip`.
* **If the chain cannot be resolved, the request is denied.** A trusted edge
  that stops sending the header denies everything rather than silently falling
  back to the edge's own address, which would be a bypass whenever your allow
  list contains the proxy's own range. Denials are logged with the address the
  decision used and why, rate-limited per service.
* **List your IPv6 ranges too.** A client reaching the proxy over IPv6 is
  matched on its IPv6 address; an IPv4-only list denies it. The proxy warns at
  deploy when a list has no IPv6 ranges. (`::ffff:` forms of IPv4 addresses are
  matched against IPv4 ranges, so those do not need listing separately.)
* **The health check path stays open**, so downstream load balancers can still
  see the service drain during a deploy. Deploying with both `--allow-ip` and a
  health check path of `/` is rejected.
* **`--client-ip-header` requires `--trusted-proxy`.** Without it the deploy is
  rejected, because the header would be ignored while appearing to be honoured.
  With it, be sure the header names one your edge *overwrites or strips* on
  every request — a header the edge merely passes through can be set by anyone.
* **Redeploying without the flag removes the restriction**, and rolling the
  proxy image back to a version without this feature removes it silently.
* **Check what the proxy actually sees.** The access log's `client_addr` is the
  connecting address; `remote_addr` is the client's own claim and is not what
  the filter uses. Under some Docker port drivers every request appears to come
  from the bridge gateway, in which case a list cannot distinguish anyone.
* **A `--path-prefix` service is routing, not a security boundary** — the same
  caveat as basic auth above.

If you use `--error-pages`, add a `403.html` to that directory.

### Rate limiting a service per client

To cap how fast a single client may hit a service, deploy it with
`--rate-limit`:

    kamal-proxy deploy service1 --target web-1:3000 --rate-limit 20

Requests over the limit get a `429` with a `Retry-After` header. The limit is
requests per second and may be fractional (`--rate-limit 0.5` is one request
every two seconds). Clients may also spend a burst back to back before the rate
applies — by default the rate rounded up, or set it explicitly:

    kamal-proxy deploy service1 --target web-1:3000 --rate-limit 20 --rate-limit-burst 100

Monitoring and internal networks can be exempted:

    kamal-proxy deploy service1 --target web-1:3000 --rate-limit 20 --rate-limit-exempt 10.0.0.0/8

Things worth knowing:

* **Behind a load balancer or CDN, set `--trusted-proxy`.** Without it every
  request carries the balancer's address, so the whole internet shares one
  bucket and the first burst locks everyone out. The client is resolved exactly
  as it is for `--allow-ip`, with the same rules about listing every hop and the
  same refusal to trust a header from an untrusted peer.
* **IPv6 clients are counted per `/64`, not per address.** Every IPv6 client
  holds at least a `/64` and can pick a fresh source address for each request,
  so counting whole addresses would let anyone walk straight past the limit. A
  `/64` is the smallest allocation guaranteed to be one subnet, so this does not
  charge one customer for another's traffic. IPv4 is counted per address.
* **Redirects are free.** A `301` from `--tls` or `--canonical-host` never
  reaches your app, so it does not spend a token — `--rate-limit 20` means
  twenty real requests per second, not ten plus their redirects.
* **It applies before the basic auth challenge**, so `--basic-auth` and
  `--rate-limit` together bound password guessing. Failed attempts spend budget.
* **The health check path stays open**, so a downstream load balancer's probes
  are never throttled — a `429` there reads as "down". Deploying with both
  `--rate-limit` and a health check path of `/` is rejected.
* **Memory is bounded.** Up to 50,000 clients are counted individually; past
  that, further clients share one bucket rather than going uncounted. Idle
  clients are forgotten once their budget has fully refilled, which by then
  carries no information.
* **Budgets are per service and reset on redeploy**, since the limiter is
  rebuilt with the service's options.
* **This is an application-level limit, not DDoS protection.** It protects your
  app from a busy or abusive client; it does not protect the proxy's own
  listener from a flood, which needs something in front of it.

If you use `--error-pages`, add a `429.html` to that directory.


### Preserving client addresses behind a load balancer

An L4 load balancer (a DigitalOcean load balancer, an AWS NLB) replaces every
connection's source address with its own, which blinds the access log,
`X-Forwarded-For`, and `--allow-ip`. If the balancer can send the [PROXY
protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt), run the
proxy with `--proxy-protocol` to read the client address it forwards:

    kamal-proxy run --proxy-protocol --proxy-protocol-allow-ip 10.0.0.0/8

Things worth knowing:

* **The header is optional per connection.** Connections that do not start
  with a PROXY preamble are served on their own address, so balancer health
  checks and direct probes keep working whether or not they send it.
* **Restrict who may assert an address.** A PROXY header is just bytes; any
  peer that can reach the port could send one and impersonate another client.
  `--proxy-protocol-allow-ip` lists the addresses or CIDR ranges (your
  balancer's private ranges) whose headers are honoured — anyone else's header
  is read and discarded, and the connection is served on its real address.
  Leaving the list empty trusts every peer, which is only safe when nothing
  but the balancer can reach the proxy's ports.
* **It applies to the HTTP and HTTPS listeners.** The preamble is read before
  the TLS handshake, as the protocol requires. The metrics listener never
  parses PROXY headers — `--metrics-allow-ip` matches the connecting address,
  and honouring a spoofable header there would undermine it. HTTP/3 runs over
  UDP, which the stream-based PROXY protocol does not cover; front it with an
  L7 balancer or leave `--http3` off behind an NLB.
* **`--allow-ip` composes with it.** Once the real client address is restored,
  service allow lists match against it directly — no `--trusted-proxy`
  configuration is needed for the balancer hop itself.
* **Both versions of the protocol are accepted** (v1 text and v2 binary),
  which covers DigitalOcean and AWS balancers without further configuration.


### Rewriting request and response headers

Security headers, CORS, and anything else your app would otherwise have to ship
itself can be set at the proxy. Each direction has three verbs, and every flag
may be given more than once:

    kamal-proxy deploy service1 --target web-1:3000 \
      --set-response-header 'Strict-Transport-Security: max-age=63072000; includeSubDomains' \
      --set-response-header "Content-Security-Policy: default-src 'self'" \
      --remove-response-header Server \
      --set-request-header 'X-Env: production'

| Verb | Effect |
|---|---|
| `--set-{request,response}-header '<name>: <value>'` | Replaces any existing values |
| `--add-{request,response}-header '<name>: <value>'` | Appends, keeping existing values |
| `--remove-{request,response}-header <name>` | Drops every value |

Things worth knowing:

* **Rules run remove → set → add**, not in the order the flags appear. Naming a
  header under both `--remove-response-header` and `--set-response-header`
  therefore leaves the value you set, whichever flag you typed first.
* **Response rules cover what your app returned.** Responses the proxy produces
  itself — error pages, the `--tls`/`--canonical-host` redirect, a `401` from
  `--basic-auth`, a `429` from `--rate-limit` — never reach your app and keep
  the proxy's own headers. This matches nginx's `add_header` default.
* **Request rules have the last word over `X-Forwarded-*`.** They are applied
  after the proxy sets those, so `--set-request-header 'X-Forwarded-Proto:
  https'` wins. They do not apply to health checks, which the proxy issues
  itself; use `--health-check-host` if a probe needs a particular `Host`.
* **Quote the value.** A value containing spaces or a comma needs shell quoting,
  but is otherwise taken verbatim — commas are not treated as separators, so
  `--add-response-header 'Access-Control-Allow-Methods: GET, POST'` is one rule.
* **`Host` cannot be rewritten on the request.** Go carries the request host
  outside the header map, so such a rule would silently do nothing; deploying
  one is rejected instead.
* **Names and values are validated at deploy time.** A malformed name, or a
  value containing a newline (which would smuggle in a second header), fails the
  deploy rather than reaching the wire.


### Redirecting and rewriting paths

`--canonical-host` moves a whole service from one host to another. To move a
path — an old URL that now lives somewhere else, or a single-page app serving
its own routes — use `--redirect` and `--rewrite`. A redirect answers the client
with a `Location`; a rewrite changes only the path your app receives, leaving
the browser's URL alone. Both may be given more than once:

    kamal-proxy deploy service1 --target web-1:3000 \
      --redirect '/old-page=/new-page' \
      --redirect '/blog/(.*)=/news/$1' \
      --redirect '/shop/(.*)=https://shop.example.com/$1;status=302' \
      --rewrite '/[^.]*=/index.html'

Things worth knowing:

* **The pattern is a regular expression matched against the whole path.**
  `/old-page` fires on `/old-page` and nothing else; write `/old(/.*)?` to cover
  what is below it too. Capture groups expand as `$1` in the replacement.
* **One hop, not two.** A rule naming a path is answered with the scheme and
  host the request was headed for anyway, so `--tls --canonical-host example.com
  --redirect '/old=/new'` sends `http://www.example.com/old` straight to
  `https://example.com/new`.
* **The query survives.** `/blog/hello?page=2` becomes `/news/hello?page=2`,
  unless the replacement carries a query of its own.
* **Redirects are `301` by default.** Add `;status=302` (or `303`, `307`, `308`)
  for anything you may want to take back — browsers cache a `301` for a long
  time.
* **A rule that resolves to the request's own URL is skipped**, so a catch-all
  like `--redirect '/(.*)=/$1'` does not send a client round in circles.
* **Rewrites are the SPA case.** `--rewrite '/[^.]*=/index.html'` hands every
  extensionless path to your app's index while `/assets/app.js` still reaches
  the file. Your app sees the rewritten path; the access log, the metrics and
  the `X-Forwarded-*` headers keep the path the client asked for.
* **Redirects win over rewrites**, and both are evaluated in the order given,
  first match wins.
* **Patterns are compiled at deploy time.** An unparseable expression, a
  replacement that is neither an absolute path nor a full URL, or a status that
  is not a redirect fails the deploy rather than the request.


### Compressing responses

The proxy can encode responses on their way back to the client, so your app does
not have to. Name the encodings you want to offer, most preferred first:

    kamal-proxy deploy service1 --target web-1:3000 --compress zstd,br,gzip

`gzip`, `br` (brotli) and `zstd` are supported. Only responses the client asked
to have encoded are touched, and the client's `q` values win — the order you give
is the tie-breaker between encodings it likes equally.

Two flags tune what qualifies:

    kamal-proxy deploy service1 --target web-1:3000 --compress gzip \
      --compress-min-length 2048 \
      --compress-content-type 'text/*,application/json,application/wasm'

Things worth knowing:

* **A response is left alone unless it will benefit.** The proxy skips anything
  your app already encoded, media types outside the compressible list, bodies
  under `--compress-min-length` (1024 bytes by default), `204`/`304` responses,
  `HEAD` requests, and byte-range replies.
* **The compressible list is an allow list.** `text/*`, JSON, XML, JavaScript,
  WASM and SVG by default, plus any `+json`/`+xml` vendor type. Anything the
  proxy does not recognise is assumed to be compressed already — images, video,
  fonts and archives all pass through. `--compress-content-type` replaces the
  list outright, and accepts exact types or a `type/*` wildcard.
* **Event streams are never compressed**, so `text/event-stream` keeps flowing
  a chunk at a time. Name it under `--compress-content-type` to override that.
* **A response flushed before it reaches the minimum is sent as-is.** Once your
  app pushes bytes to the client, the proxy stops holding any back.
* **`Vary: Accept-Encoding` is set on every compressible response**, whether or
  not this particular client got an encoded body, so a cache in front of the
  proxy keeps the two representations apart. A strong `ETag` is weakened to
  `W/"..."` when the body is encoded, for the same reason.
* **The built-in error pages are not compressed.** They are rendered above the
  router, outside any one service's settings. Pages you supply with
  `--error-pages` are compressed like anything else.


### Automatic TLS

Kamal Proxy can automatically obtain and renew TLS certificates for your
applications. To enable this, add the `--tls` flag when deploying an instance:

    kamal-proxy deploy service1 --target web-1:3000 --host app1.example.com --tls

Automatic TLS requires that hosts are specified (to ensure that certificates
are not maliciously requests for arbitrary hostnames).

Additionally, when using path-based routing, TLS options must be set on the
root path. Services deployed to other paths on the same host will use the same
TLS settings as those specified for the root path.


### On-demand TLS

Instead of specifying a static list of hosts, Kamal Proxy can also obtain TLS
certificates dynamically, for any host approved by an HTTP endpoint of your
choice. This is useful when the full set of hosts is not known at deploy time,
such as when serving customer domains.

To enable this, specify `--tls-on-demand-url` (instead of `--host`) when
deploying:

    kamal-proxy deploy service1 --target web-1:3000 --tls --tls-on-demand-url="http://localhost:4567/check"

The URL may be:

- An external URL (like `http://localhost:4567/check`), which Kamal Proxy will
  call directly, or
- A path (like `/check`), which Kamal Proxy will route through the service to
  your application, letting the application decide which hosts to allow.

Before issuing a certificate for a host, Kamal Proxy will send a `GET` request
to the endpoint, with the hostname in a `host` query parameter (for example,
`?host=app1.example.com`) and matching `Host` header. A `200` response allows
certificate issuance; any other response denies it, and the status code and up
to 256 bytes of the response body are logged to help with debugging. Checks
time out after 2 seconds, denying issuance for that attempt.


### Custom TLS certificate

When you obtained your TLS certificate manually, manage your own certificate authority,
or need to install Cloudflare origin certificate, you can manually specify path to
your certificate file and the corresponding private key:

    kamal-proxy deploy service1 --target web-1:3000 --host app1.example.com --tls --tls-certificate-path cert.pem --tls-private-key-path key.pem


### Mutual TLS (mTLS)

To require that clients present a certificate, pass a PEM bundle of the
certificate authorities they must chain to with `--tls-client-ca-path`.
Connections that present no certificate, or one signed by any other authority,
are rejected during the TLS handshake:

    kamal-proxy deploy service1 --target web-1:3000 --host app1.example.com --tls --tls-certificate-path cert.pem --tls-private-key-path key.pem --tls-client-ca-path ca.pem

The requirement is per-service and applies to the hosts that service serves, so
services on the same proxy can have different client certificate rules. This is
how you enable [Cloudflare Authenticated Origin
Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/),
ensuring only Cloudflare can reach your origin.

Note that a service deployed without `--host` — one using `--tls-on-demand-url`
or `--tls-domains-source` — serves every hostname no other service claims, so its
client CA applies to all of them.


### Minimum TLS version

The HTTPS listener negotiates TLS 1.2 and above by default. To refuse TLS 1.2 as
well and serve only TLS 1.3, start the proxy with `--min-tls` (or the `MIN_TLS`
environment variable):

    kamal-proxy run --min-tls 1.3

Accepted values are `1.2` and `1.3`. TLS 1.0 and 1.1 cannot be enabled — they are
deprecated by [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) and Go's TLS
stack already declines to serve them, so the proxy refuses to start rather than
pretend the setting took effect. The `tls1_2` / `tls1_3` spellings are accepted
too, so a configuration written against upstream kamal-proxy keeps working.

This is a listener-wide setting: it applies to every service, including hosts
that require client certificates. The HTTP/3 listener is always TLS 1.3, since
QUIC is only defined over TLS 1.3 ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)),
and `--min-tls` neither lowers nor raises it.

Raising the minimum locks out clients that cannot reach it, and they fail during
the handshake — before the request reaches the HTTP layer, so nothing appears in
the access log. Check what your clients actually negotiate before setting `1.3`.

Cipher suites are deliberately not configurable. Go does not allow selecting TLS
1.3 cipher suites at all, and its TLS 1.2 defaults already exclude the RC4, 3DES
and static-RSA suites that a hardening baseline asks you to remove — so a cipher
flag could only weaken the proxy, while silently doing nothing on TLS 1.3.


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
