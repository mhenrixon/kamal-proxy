# kamal-proxy (mhenrixon fork)

Fork of [basecamp/kamal-proxy](https://github.com/basecamp/kamal-proxy) carrying the cert features upstream doesn't ship: SAN certificate batching and wildcard certs via DNS-01. Published as `ghcr.io/mhenrixon/kamal-proxy`; the Go module, binary, RPC service, and socket all stay `kamal-proxy` on purpose. Consumed by the `dash` gem fork in `../kamal`.

## Tech Stack

- **Go**: version from `go.mod` (tracks upstream's toolchain bumps)
- **RPC**: net/rpc over a unix socket (`kamal-proxy.sock`) between CLI and server
- **Certs**: autocert + go-acme/lego (SAN batching, DNS-01 wildcard providers)
- **Image**: multi-arch (amd64+arm64) via buildx, published by CI on tag push

## Critical Rules

### Never Do

1. **NO renaming of module/binary/RPC/socket** — `kamal-proxy` is load-bearing: the RPC name is registered once in `internal/server/commands.go` and dialed by 9 client call sites; the Dockerfile copies `bin/kamal-proxy`; the kamal gem execs `kamal-proxy run`
2. **NO commits on `main`** — fast-forward-only mirror of upstream
3. **NO three-segment `v*` tags** — upstream owns them; fork tags are four-segment `vX.Y.Z.N`
4. **NO publishing without the `org.opencontainers.image.title=kamal-proxy` label** — kamal prunes proxy images by it (set in `docker-publish.yml`)
5. **NO pointing deploys at `:latest`** — kamal parses the image tag as a version; non-numeric tags crash the check
6. **NO `git push --tags`** — single-tag pushes only (`git push origin tag v0.9.2.1`)

### Always Do

1. **Four-segment tags** `v<upstream-base>.<counter>` (e.g. `v0.9.2.1`) — sorts above the base and below the next upstream release under Gem::Version
2. **Release via `script/release-dash`** — validates the tag grammar, tests, tags, pushes; CI builds and publishes
3. **`go mod tidy` after merging main into cert branches** — take main's dep graph, keep lego
4. **`make test` + `gofmt -l` clean before pushing** — CI enforces formatting

## Commands

```bash
make build                                  # Build bin/kamal-proxy
make test                                   # go test ./...
make docker                                 # Local image build (smoke test)
script/release-dash v0.9.2.1                # Tag + push; CI publishes to ghcr
docker buildx imagetools inspect ghcr.io/mhenrixon/kamal-proxy:v0.9.2.1   # Verify multi-arch
git fetch upstream --tags --prune           # Start of every sync
```

## Architecture

```
Layer 3: cmd/kamal-proxy           (main entry point)
Layer 2: internal/cmd              (cobra CLI; RPC client for deploy/remove/...)
Layer 1: internal/server           (Router, Service, LoadBalancer, cert managers, RPC server)
Layer 0: unix socket + state files (~/.config/kamal-proxy, kamal-proxy.sock)
```

## The mental model

> The binary has no version command. The image tag IS the version — the kamal gem docker-inspects the running container and compares the tag with Gem::Version. Ship behavior in the image, meaning in the tag.

## Branch map

| Branch | Contents | Conflict surface vs main |
|---|---|---|
| `main` | basecamp mirror, ff-only | — |
| `dash` | integration + release: publish workflow + cert features merged | — |
| `san-certificate-batching` | SAN cert batching (`internal/server/san_cert_manager.go`), `--acme-email`/`--acme-directory` | run.go, config.go, router.go, go.mod |
| `wildcard-certs` | DNS-01 wildcard certs (`internal/server/acme/`, cert registry), `--acme-dns-provider` etc. | run.go, config.go, router.go, go.mod |
| `feat/loadbalancing` | SUPERSEDED — upstream absorbed multi-target LB natively (`load_balancer.go`, reader/writer split); the branch only retains a standalone `TargetPool` module. Not merged into `dash`; candidate for deletion. | — |

The two cert branches deliberately overlap in run.go/config.go/router.go — their union lives on `dash` (single `--acme-email`/`--acme-directory` flag registration feeding both the SAN manager and the certificate registry).

## Release & image

Tag push (`vX.Y.Z.N`) → `.github/workflows/docker-publish.yml` → multi-arch build → `ghcr.io/mhenrixon/kamal-proxy:vX.Y.Z.N` + `:latest`. `GITHUB_TOKEN` authenticates; the ghcr package must stay PUBLIC (kamal deploys and integration tests pull anonymously). The kamal fork's `MINIMUM_VERSION` must always name a published tag — release here FIRST, then the gem.

## Testing

- `make test` — full Go suite, no Docker needed
- `make docker && docker run --rm kamal-proxy kamal-proxy -h` — image smoke test
- CI (`ci.yml`): build + test + golangci-lint + actionlint/zizmor on `main` and `dash`

## More Documentation

- `.claude/rules/upstream-sync.md` — sync runbook, conflict playbook
- Gem fork: `../kamal/CLAUDE.md` — gem-side contract and release ordering
