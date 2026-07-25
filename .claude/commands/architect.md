---
description: "Coordinates development across dash-proxy layers (cmd -> RPC -> server). Use when planning multi-layer features, orchestrating implementation order, or designing new subsystems."
model: opus
argument-hint: "feature or task to coordinate"
allowed-tools: Read, Grep, Glob, Bash(make test:*), Bash(make build:*), Bash(make lint:*), Bash(gofmt:*), Bash(go build:*), Bash(git status:*), Bash(git diff:*), Bash(git log:*)
---

# Dash-Proxy Architect Mode

You are now in **Architect Mode** — coordinating development across all dash-proxy layers.

## Why This Skill Exists

dash-proxy spans a strict three-layer cake (CLI → RPC → server) plus a persisted-state boundary. Without coordination, a feature lands in the wrong layer, skips the JSON round-trip contract, or breaks the "never rename kamal-proxy" constraint. This mode plans implementation order before code is written.

## Dash-Proxy Architecture Layers

```
Layer 3: cmd/kamal-proxy         main entry point (thin — cobra Execute() only)
Layer 2: internal/cmd            cobra CLI + RPC client (deploy.go, run.go, pause.go, ...)
         ---- unix socket RPC (kamal-proxy.sock) ----
Layer 2: internal/server/commands.go   RPC arg structs + CommandHandler (registered ONCE via sync.Once)
Layer 1: internal/server         Router, Service, LoadBalancer, Target, cert managers
Layer 0: state + certs           ~/.config/kamal-proxy/*.json (Service.MarshalJSON round-trip), autocert/lego stores
```

Reference: `CLAUDE.md` "Architecture" section for the one-line version; `ROADMAP.md` "Implementation notes" for the anchor table this mode is built from.

## Typical Implementation Flow

1. **Options struct** — add the field to `ServiceOptions` (`internal/server/service.go:82`, per-service), `TargetOptions` (`internal/server/target.go:65`, per-target), or `DeploymentOptions` (`service.go:76`, one-shot) — pick the narrowest scope that fits
2. **JSON round-trip** — if it lives on `ServiceOptions`/`TargetOptions`, wire `Service.MarshalJSON`/`UnmarshalJSON` (`service.go:273`/`294`) and default it safely against old state files already on disk
3. **RPC arg struct** — add/extend the matching struct in `internal/server/commands.go` (e.g. `DeployArgs`) and the `CommandHandler` method that consumes it
4. **CLI flag** — register the flag in `internal/cmd/deploy.go` / `run.go` (or the relevant command file), wire it into the RPC args, `PreRunE`-validate if it has a grammar
5. **Server behavior** — implement in `Router`/`Service`/`LoadBalancer`/`Target`/middleware, whichever owns the concern
6. **Tests** — table-driven Go tests colocated per file (`*_test.go`), `make test` green, `gofmt -l` clean
7. **Gem-side plumbing** — if reachable from `deploy.yml`, mirror into `../kamal` (`lib/kamal/configuration/proxy.rb`; three files if the load-balancer tier also carries it — see that repo's CLAUDE.md)

## When to Delegate vs. Do Directly

**Delegate when**:
- Multiple files across a layer need changes (e.g. new middleware + Router wiring + metrics)
- Deep domain expertise is needed (ACME/lego internals, TLS handshake gating in `router.go GetCertificate`)
- Work is clearly scoped to one layer

**Handle directly when**:
- Simple, single-file changes
- Cross-cutting concerns touching cmd + RPC + server in lockstep (a new flag end-to-end)
- Quick fixes or minor adjustments

## Decision Guidelines

| Decision | Use When |
|----------|----------|
| New `ServiceOptions` field | Feature is configurable per service (e.g. header rules, rate limits) |
| New `TargetOptions` field | Feature is configurable per target (e.g. per-target timeout) |
| New `DeploymentOptions` field | Feature is a one-shot deploy-time flag, not persisted behavior |
| New RPC command | New verb entirely (rare — prefer extending `DeployArgs` et al.) |
| New middleware | Cross-cutting request/response behavior (see `service.go:458 createMiddleware` chain) |
| New cert manager path | Only for genuinely new ACME flows — SAN batching and wildcard DNS-01 already exist, extend don't duplicate |
| State file migration | New persisted field must default-safe against JSON already on disk |

## Integration Points

| When working on... | Also consider... |
|-------------------|------------------|
| `ServiceOptions`/`TargetOptions` field | `MarshalJSON`/`UnmarshalJSON` round-trip + old-state defaulting |
| New CLI flag | RPC arg struct in `commands.go` + gem-side flag mapping in `../kamal` |
| `LoadBalancer` changes | `health_check.go`, `rollout_controller.go` (both read target state) |
| New middleware | Ordering in `service.go:458 createMiddleware`, and the SSE/WebSocket bypass in `response_buffer_middleware.go:86` |
| TLS/cert work | Both `san_cert_manager.go` (SAN batching) and `cert_registry.go` (wildcard DNS-01) — dash merged both, check which owns the surface |
| Metrics | `internal/metrics/metrics.go` — wire the setter, don't just define it (see ROADMAP R1) |
| Anything upstream also touches | `.claude/rules/upstream-sync.md` conflict table — plan merge order, not just feature order |

## Common Mistakes to Avoid

| Wrong | Right |
|-------|-------|
| Start in `internal/server` | Start with the options struct + JSON round-trip, then RPC, then server |
| New field with no default-safety | Every persisted field must tolerate absence in old state files |
| Rename anything `kamal-proxy` | Binary/module/RPC-name/socket are load-bearing (CLAUDE.md Never Do #1) — never touch |
| Register RPC name twice | `CommandHandler` registration is `sync.Once` — extend existing methods, don't re-register |
| Skip `gofmt` | CI enforces `gofmt -l` clean; run it before every push |
| Forget the gem side | Anything in `deploy.yml` needs `../kamal` plumbing too (ROADMAP implementation notes) |
| Plain `v*` git tag | Fork tags are four-segment `vX.Y.Z.N`; three-segment is upstream's namespace |
| Skip tests | TDD — tests first, table-driven, colocated `*_test.go` |

## Verification Checklist

- [ ] Implementation order planned bottom-up (options struct → RPC → server → CLI flag)
- [ ] Dependencies between layers identified (see Integration Points)
- [ ] New persisted fields are JSON round-trip safe and default-safe against old state
- [ ] `kamal-proxy` binary/RPC/socket name untouched
- [ ] Gem-side plumbing identified if the feature is deploy.yml-reachable
- [ ] Tests cover all touched layers
- [ ] `make test` passes
- [ ] `gofmt -l internal/ cmd/` empty
- [ ] `make lint` noted for CI (golangci-lint isn't installed locally — don't block on it)

## Handoff

When complete, summarize:
- Implementation plan with layer order (options struct → RPC → server → CLI → gem)
- Files to create/modify per layer, with anchors (`file.go:line`) where known
- Integration points identified
- Architectural decisions made, and which ROADMAP.md item (if any) this advances

Now, coordinate dash-proxy development with this architectural perspective.
