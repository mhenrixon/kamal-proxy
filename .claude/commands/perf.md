---
description: "Benchmark the current branch against main. Use when a change touches a hot path (router, load balancer, cert manager, buffer middleware) or when asked to measure performance."
model: sonnet
argument-hint: "optional: a specific benchmark name (e.g. BenchmarkServiceMap_WilcardRouting)"
allowed-tools: Bash(git worktree:*), Bash(git branch:*), Bash(go test:*), Bash(make bench:*), Bash(make test:*), Bash(cp:*), Bash(rm:*), Bash(diff:*), Bash(gofmt:*), Read, Grep, Glob, Write
---

# Performance Command

Measure, don't guess. This command produces a **same-machine before/after** so
any performance claim is backed by numbers.

## The non-negotiable rule

**Measure BEFORE you change.** A delta you didn't baseline is not a delta. If
a change already landed without a baseline, reconstruct one from `main` in a
**worktree** — never the primary tree, and never on `dash`. `main` is a
fast-forward-only mirror of upstream (`CLAUDE.md`); a worktree keeps the
baseline checkout disposable and never risks a stray commit landing there.

## Workflow

### 1. Baseline `main` (before)

```bash
git worktree add --detach /tmp/kamal-proxy-baseline main
(cd /tmp/kamal-proxy-baseline && go test -bench=. -benchmem -run=^# ./...) > /tmp/before.txt
```

### 2. Measure the branch (after)

```bash
make bench > /tmp/after.txt
diff /tmp/before.txt /tmp/after.txt
git worktree remove --force /tmp/kamal-proxy-baseline
```

For a single hot path, scope both runs with `-bench=<name>`, e.g.:

```bash
go test -bench=BenchmarkServiceMap_WilcardRouting -benchmem -run=^# ./internal/server/...
```

`$ARGUMENTS`: if a specific benchmark is named, scope both the baseline and
branch runs to it with `-bench=$ARGUMENTS`; otherwise run the full suite
(`make bench`, which is `go test -bench=. -benchmem -run=^# ./...`).

### 3. Report HONESTLY

- Report ns/op AND B/op + allocs/op — `go test -benchmem` gives all three.
  Rising allocs/op on an unrelated change is a regression even if ns/op holds.
- **Distinguish method-level from system-level wins.** A faster
  `ServiceForRequest` lookup does NOT mean a faster deploy — ACME round-trips
  to the CA and target health checks dominate wall-clock there. Say which
  layer the number describes.
- Go microbenchmarks are noisy on shared/laptop hardware. If a delta is
  within run-to-run variance, say "within noise" — don't round it into a win.
  Re-run (`-count=5` piped through `benchstat` if installed) before claiming
  anything under ~5%.
- If you only measured *after* (no clean baseline), say so explicitly.

### 4. Keep perf continuous

- [ ] A benchmark exists for the changed hot path. Add one if missing (see
      `internal/server/service_map_test.go` for the pattern — table-driven
      `b.Run` subtests using `for b.Loop() { ... }`).
- [ ] The before/after numbers are in the PR body.
- [ ] `gofmt -l internal/ cmd/` clean before pushing — CI enforces it
      (`CLAUDE.md` Always Do #4).

## The hot paths to watch

| Path | Where | Note |
|------|-------|------|
| `ServiceMap.ServiceForRequest` | `internal/server/service_map.go`, benched in `service_map_test.go` | Host/path routing — runs on every request before a target is even chosen. |
| `LoadBalancer.claimTarget` / `nextTarget` | `internal/server/load_balancer.go:200,216` | Per-request target selection; round-robin today, gains a weight field under ROADMAP R5. |
| `LoadBalancer.StartRequest` | `internal/server/load_balancer.go:174` | Wraps the whole proxied request — connection accounting + affinity cookie overhead. |
| `Router.ServeHTTP` / `GetCertificate` | `internal/server/router.go:120,293` | Per-request dispatch and per-handshake cert lookup (SAN manager first, then registry — ROADMAP R4 on-demand TLS adds a gate here). |
| `SANCertManager.getCertForDomain` / `GetCertificate` | `internal/server/san_cert_manager.go:283,442` | In-memory cert cache lookup on the TLS handshake path — must stay allocation-light since it runs per-handshake, not per-request. |
| Buffer middlewares | `internal/server/request_buffer_middleware.go`, `response_buffer_middleware.go` | Body buffering for retries/replay (ROADMAP R2) — watch retained bytes, not just latency. |

No benchmark exists yet for the load balancer or cert manager paths — write
one alongside the change that touches them rather than reasoning from the
`ServiceMap` numbers, which only cover routing.

## What this command is not

There is no `rake`, no RSpec, no bundler here — this is a Go module
(`go.mod` still declares `github.com/basecamp/kamal-proxy`; the module name
is unrenamed on purpose, see `CLAUDE.md` Never Do #1). Everything above is
`go test -bench`. If the work in question is actually about deploy-time
behavior (rollout speed, health-check convergence, ACME issuance latency)
rather than a hot code path, that isn't a Go benchmark — profile the deploy
steps directly (`kamal-proxy deploy` timing, target health-check intervals in
`internal/server/health_check.go`) instead of fabricating a synthetic bench
for it.
