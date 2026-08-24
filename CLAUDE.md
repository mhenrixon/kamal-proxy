# dash-proxy

**dash-proxy** (`zoolutions/dash-proxy`). Started as a fork of [basecamp/kamal-proxy](https://github.com/basecamp/kamal-proxy); the break is now clean — no upstream remote, no sync branch, their code arrives only by deliberate cherry-pick if ever. Carries the cert features they don't ship: SAN certificate batching and wildcard certs via DNS-01. Published as `ghcr.io/zoolutions/dash-proxy`; the Go module, binary, RPC service, socket, and image title label all stay `kamal-proxy` on purpose until the server-artifact rename ships a migration bridge. Consumed by the `dash` gem in `../kamal`.

## Tech Stack

- **Go**: version from `go.mod` (tracks upstream's toolchain bumps)
- **RPC**: net/rpc over a unix socket (`kamal-proxy.sock`) between CLI and server
- **Certs**: autocert + go-acme/lego (SAN batching, DNS-01 wildcard providers)
- **Image**: multi-arch (amd64+arm64) via buildx, published by CI on tag push

## Critical Rules

### Never Do

1. **NO renaming of module/binary/RPC/socket** — `kamal-proxy` is load-bearing: the RPC name is registered once in `internal/server/commands.go` and dialed by 9 client call sites; the Dockerfile copies `bin/kamal-proxy`; the kamal gem execs `kamal-proxy run`
2. **NO upstream syncs** — the fork network is left and the `upstream` remote removed; `main` is this repo's only long-lived branch and everything lands there via PR
3. **NO suffix tags** like `v1.0.0-rc1` — the gem compares the image tag with `Gem::Version`, which reads a hyphen suffix as a prerelease sorting *below* the release it names
4. **NO publishing without the `org.opencontainers.image.title=kamal-proxy` label** — the dash gem prunes proxy images by it (set in `docker-publish.yml`); it stays `kamal-proxy` until the server-artifact rename ships a bridge
5. **NO pointing deploys at `:latest`** — kamal parses the image tag as a version; non-numeric tags crash the check
6. **NO `git push --tags`** — single-tag pushes only (`git push origin tag v1.0.0.0`)

### Always Do

1. **Four-segment tags** `vX.Y.Z.N` (e.g. `v1.0.0.0`) — the shape is unchanged, the meaning is not: all four segments are ours to choose. They used to be `<upstream-base>.<counter>`, derived from whatever basecamp had tagged; we own dash-proxy now, so the number reflects what shipped here
2. **Release via `script/release-dash`** — validates the tag grammar, tests, tags, pushes; CI builds and publishes. Its grammar and `docker-publish.yml`'s tag filter must stay in step, or a tag pushes and nothing builds
3. **`go mod tidy` after merging main into cert branches** — take main's dep graph, keep lego
4. **`make test` + `gofmt -l` clean before pushing** — CI enforces formatting

## Commands

```bash
make build                                  # Build bin/kamal-proxy
make test                                   # go test ./...
make docker                                 # Local image build (smoke test)
script/release-dash v1.0.0.0                # Tag + push; CI publishes to ghcr
docker buildx imagetools inspect ghcr.io/zoolutions/dash-proxy:v1.0.0.0   # Verify multi-arch
```

## Architecture

```
Layer 3: cmd/kamal-proxy           (main entry point)
Layer 2: internal/cmd              (cobra CLI; RPC client for deploy/remove/...)
Layer 1: internal/server           (Router, Service, LoadBalancer, cert managers, RPC server)
Layer 0: unix socket + state files (~/.config/kamal-proxy, kamal-proxy.sock)
```

## The mental model

> The binary has no version command. The image tag IS the version — the `dash` gem docker-inspects the running container and compares the tag with `Gem::Version`. Ship behavior in the image, meaning in the tag.

## Branch map

**`main` is the only long-lived branch** (since the 2026-08 clean break — it carries what the
`dash` branch used to). New work branches off `main` and PRs back into `main`. The historical
feature branches (`san-certificate-batching`, `wildcard-certs`) are merged and dormant;
`feat/loadbalancing` is superseded (upstream absorbed multi-target LB natively) and a candidate
for deletion.

## Release & image

Tag push (`vX.Y.Z.N`) → `.github/workflows/docker-publish.yml` → multi-arch build → `ghcr.io/zoolutions/dash-proxy:vX.Y.Z.N` + `:latest`. `GITHUB_TOKEN` authenticates; the ghcr package must stay PUBLIC (dash deploys and integration tests pull anonymously). The dash gem's `MINIMUM_VERSION` must always name a published tag — release here FIRST, then the gem. The old `ghcr.io/zoolutions/kamal-proxy` package stays published untouched — released gem versions still pull it.

## Testing

- `make test` — full Go suite, no Docker needed
- `make docker && docker run --rm kamal-proxy kamal-proxy -h` — image smoke test
- CI (`ci.yml`): build + test + golangci-lint + actionlint/zizmor on `main`

## Slash Commands

| Command | Purpose |
|---------|---------|
| `/lfg` | Full autonomous workflow: branch off `main` → understand → plan → TDD → verify → PR into `main` |
| `/plan` | Read-only planning → GitHub issue or `docs/plans/` markdown (execute with `/lfg`) |
| `/architect` | Coordinate work across the cmd → RPC → server layers |
| `/tdd` | Enforce RED → GREEN → REFACTOR with Go table-driven tests |
| `/security` | Audit TLS/cert handling, request parsing, header forwarding, ACME, the unix socket |
| `/perf` | Baseline vs `main` in a worktree via `make bench` on the real hot paths |
| `/review-pr` | Review a PR for pattern + fork-constraint compliance |
| `/github-review-pr` | Full PR pass: fix CI failures, then process review comments |
| `/github-review-failures` | Diagnose + fix CI failures until green |
| `/github-review-comments` | Process unresolved PR review comments |

Commands pin a model tier via frontmatter aliases (`sonnet` implementation, `opus` orchestration/security/review, `fable` read-only planning) so they track the latest model per tier.

## More Documentation

- `ROADMAP.md` — proxy-side roadmap with code anchors (strategy + sequencing in ../kamal/ROADMAP.md)
- `.claude/rules/` — coding-style, git-workflow, testing, agents, performance, upstream-sync
- `.claude/commands/` — the slash commands above
- Gem fork: `../kamal/CLAUDE.md` — gem-side contract and release ordering
