# dash-proxy Roadmap

Proxy-side roadmap for the dash fork. The cross-repo release sequencing, strategic frame, and gem-side items live in the twin `ROADMAP.md` in [`../kamal`](https://github.com/mhenrixon/kamal); this file carries the proxy work with code anchors. Strategy in one line: own what basecamp rejected (headers #62, rate limiting #20, compression #19, PROXY protocol #31), port what they left stuck (#63 on-demand TLS, #204 mTLS, #216 basic auth, #199 min-TLS), and ship the table-stakes resilience knobs every other proxy has.

## R1 — Foundations & fixes (v0.9.2.2) — all S-sized

| Item | Anchor |
|---|---|
| **Start `CertificateRenewalManager`** — defined but never started in `internal/cmd/run.go`; wildcard/registry certs currently renew only lazily during TLS handshakes within 24h of expiry | `internal/server/cert_renewal.go:14` (12h check / 30-day threshold), wire `.Start()` after `registry.Initialize` |
| **Wire the 3 certificate Prometheus metrics** — expiry gauge, renewals counter, totals gauge have setters but no callers | `internal/metrics/metrics.go:81-101` → call from cert managers |
| **Slowloris / server-timeout defaults** — no `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout` on any listener (all Go zero = unlimited) | discussion basecamp/kamal-proxy#196; `internal/server/server.go:141,150,192`; make configurable via `run` flags, ship safe defaults |

## R2 — Timeouts & resilience

| Item | Evidence | Anchor |
|---|---|---|
| **Per-route timeouts** — per-`(host, path-prefix)` override of target timeout; each binding is already a candidate carrier | #53; SSE cluster #46/#54/#137/#186 | `pathBinding` (`internal/server/service_map.go:15`) + thread into `Target.createProxyHandler` (`internal/server/target.go:293`) |
| **Whole-request deadline** — `--target-timeout` maps to `Transport.ResponseHeaderTimeout` only (`target.go:302`); long bodies can run forever | #53 | deadline middleware in `createMiddleware` (`internal/server/service.go:458`); must exempt WebSocket/SSE (`response_buffer_middleware.go:86` bypass logic) |
| Retries / hold-until-healthy — retry idempotent methods on next target; brief hold during redeploy blips | #71; Caddy `lb_try_duration` | `LoadBalancer.StartRequest` (`internal/server/load_balancer.go:174`); replay needs request buffering (`internal/server/buffer.go`) |
| Custom upstream 502/503 error pages | nginx `proxy_intercept_errors`, Apache `ProxyErrorOverride` | DONE — `--intercept-errors` (`internal/server/error_intercept_middleware.go`). Errors the *proxy* raises already rendered through `ErrorPageMiddleware`; the gap was error responses the *target* wrote itself |
| Upstream pool tuning — `MaxConnsPerHost`, `IdleConnTimeout`, keep-alives | inventory | DONE — `--target-max-conns`, `--target-max-idle-conns`, `--target-idle-conn-timeout`, `--target-dial-timeout`, `--target-disable-keep-alives` (`internal/server/target_pool.go`). The transport was a bare struct literal, so the unset fields were Go zero rather than `http.DefaultTransport`'s values: idle conns never expired *and* were never staleness-checked before reuse, and there was no dial timeout at all. Zero in `TargetOptions` now means "proxy default", resolved server-side so restored state files and older RPC clients get it too |

## R3 — Security & access

| Item | Evidence | Anchor |
|---|---|---|
| Basic auth per service | port PR #216 (open); kamal#1604 | DONE — `--basic-auth <user>:<pass>` (`internal/server/basic_auth.go`). Deliberately **not** a `createMiddleware` middleware: that chain wraps `serviceRequestWithTarget`, which is where the HTTPS redirect lives, so a middleware there challenges before the 301 and the browser sends the password in cleartext. The check sits inline after `handleRedirectsIfNeeded`. Credentials are hashed CLI-side (salted SHA-256), so no plaintext crosses the RPC socket or reaches the state file. Per-path scoping is served by deploying a `--path-prefix` service with its own credential |
| IP allow list (CIDR) | discussions #143/#144 | DONE — `--allow-ip`/`--trusted-proxy` on deploy, `--metrics-allow-ip` on run (`internal/server/ip_allow_list.go`). Allow-only; a static deny list is the wrong tool for the abuse-blocking people reach for it with. **Not** a `createMiddleware` middleware — that chain includes the cert manager's handler, so filtering there breaks ACME HTTP-01 and certificates fail to renew weeks later. Runs as the first check in `serviceRequestWithTarget`, before the HTTPS redirect. Matches the connecting peer, never a header, unless the peer is inside `--trusted-proxy`. The `logging_middleware.go:70` anchor this row used to name is the trap: that function's `remote_addr` is raw `X-Forwarded-For` with no trust check |
| Per-IP rate limiting (token bucket + burst + allowlist) | rejected #20 | global chain (`server.go:211 buildHandler`) or per-service; `golang.org/x/time/rate` |
| PROXY protocol | rejected #31, discussion #41 | `go-proxyproto` listener wrap in `server.go`; `run` flag |
| mTLS (`--tls-client-ca-path`) | port PR #204 (open); kamal#1628 | `tls.Config.ClientCAs/ClientAuth` on HTTPS listener (`server.go:158`) |

## R4 — TLS & custom domains

| Item | Evidence | Anchor |
|---|---|---|
| **On-demand TLS with `ask` endpoint** | port PR #63 — 18mo open, prod-tested (LocomotiveCMS); discussions #141/#221 | integrate with dash's `CertificateRegistry` (`internal/server/cert_registry.go`) rather than the PR's standalone path; per-handshake gate in `router.go:293 GetCertificate` |
| Min-TLS version / ciphers (no `MinVersion` today → TLS 1.2 default) | port PR #199 | `server.go:158` TLS config; `run` flag |
| Cert observability — dashboards/alerts on the R1-wired metrics | — | `internal/metrics` |

## R5 — Traffic shaping & headers

| Item | Evidence | Anchor |
|---|---|---|
| Header rules (req/resp add/remove/set; CORS/HSTS/CSP presets) | rejected #62/#25 | request: `Target.rewrite/forwardHeaders` (`target.go:307/344`); response: `ReverseProxy.ModifyResponse` in `createProxyHandler` (`target.go:296`) |
| Weighted canary (`--target=b;weight=5`) | kamal#941, #8 | `LoadBalancer.nextTarget` (`load_balancer.go:216`) — currently pure round-robin |
| Redirect/rewrite rules | #35; kamal discussions #1214/#97 | extend canonical-host redirect mechanics (merged #153) |
| Compression (gzip/zstd/brotli) | rejected #19 | response middleware in `createMiddleware`; must coordinate with the streaming bypass (`response_buffer_middleware.go:86`) |
| Scale-to-zero | port PR #197 (open) | `PauseController` states (`pause_controller.go`) are the natural base |
| Observability batch — log format selection, OTel traceparent, metrics path excludes | #213 counter-proposal | `logging_middleware.go:81` (fixed JSON today); `request_id_middleware.go` |

## Implementation notes (apply to every feature)

- New per-service knobs go in `ServiceOptions` (`service.go:82`), per-target in `TargetOptions` (`target.go:65`), one-shot in `DeploymentOptions` (`service.go:76`); flags register in `internal/cmd/deploy.go` / `run.go`; RPC arg structs in `internal/server/commands.go:19-63`.
- `ServiceOptions`/`TargetOptions` are JSON-persisted across restarts — new fields must round-trip `Service.MarshalJSON/UnmarshalJSON` (`service.go:273/294`) and be default-safe against old state files.
- Never rename module/binary/RPC/socket (see CLAUDE.md Never Do #1). Image tags stay four-segment.
- Anything reachable from deploy.yml also needs gem-side plumbing — see the flag-mapping table workflow in `../kamal` (one file for plain options: `lib/kamal/configuration/proxy.rb`; three when the loadbalancer tier must carry it too).
