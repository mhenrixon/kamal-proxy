# Agent Orchestration Rules

## Available Agents

| Agent | Purpose | When to Use |
|-------|---------|--------------|
| Explore | Codebase exploration | Finding files, tracing RPC call sites, understanding cert-manager patterns |
| Plan | Implementation planning | New cert providers, router/target changes, upstream-merge conflict strategy |
| general-purpose | Multi-step tasks | Cross-branch searches, multi-file refactors, release prep |

## Immediate Agent Usage

Use agents PROACTIVELY without waiting for user prompt:

1. **Cert/ACME feature requests** -> Plan agent first — `san_cert_manager.go` and `acme/` have union-merge conflict surface with `dash`, get the approach right before touching code
2. **"Where does X happen" questions** -> Explore agent over `internal/server` or `internal/cmd`, not manual grep
3. **Multi-file searches** -> Explore agent (not direct Glob/Grep) — e.g. finding all 9 RPC client call sites for a `commands.go` rename
4. **Upstream-merge conflict resolution** -> Plan agent, cross-reference `.claude/rules/upstream-sync.md`'s conflict playbook first

## Parallel Execution

**ALWAYS** use parallel Task execution for independent operations:

```markdown
# GOOD: Parallel execution
Launch multiple agents simultaneously:
1. Agent 1: Explore router.go + service.go for target-selection logic
2. Agent 2: Check cert_registry.go vs san_cert_manager.go overlap
3. Agent 3: Review test coverage in load_balancer_test.go

# BAD: Sequential when unnecessary
First explore router.go, wait, then check cert_registry.go, wait, then review tests...
```

## Exploration Surfaces (this repo)

Point Explore agents at the actual layers, not the whole tree:

| Surface | Path | Contents |
|---|---|---|
| Entry point | `cmd/kamal-proxy` | `main.go` only |
| CLI + RPC client | `internal/cmd` | cobra commands (`deploy.go`, `run.go`, `rollout_*.go`); each dials the unix socket |
| RPC server + core | `internal/server` | `router.go`, `service.go`, `load_balancer.go`, `target.go` — request path |
| Cert managers | `internal/server` | `san_cert_manager.go` (SAN batching, fork-only), `cert_registry.go` + `acme/` (wildcard DNS-01, fork-only), `registry_cert_manager.go` (upstream) |
| Middleware | `internal/server` | `*_middleware.go` — logging, buffering, error pages, request id |
| Docs | repo root | `CLAUDE.md`, `ROADMAP.md`, `.claude/rules/upstream-sync.md` |

## When NOT to Use Agents

Use direct tools when:
- Reading a specific known file path (e.g. `internal/server/router.go`)
- Single-file edits
- Running `make build`, `make test`, `make docker`, or `script/release-dash`
- Checking `gofmt -l` output before a commit

## Verification After Agent Work

Agents don't run checks for you. After any agent-produced diff:

```bash
make test              # go test ./...
gofmt -l internal/ cmd/  # must be empty — CI enforces, golangci-lint isn't installed locally
```

`make lint` requires golangci-lint (CI-only) — don't rely on it locally as a gate.

## Release & Cross-Repo Agents

Release ordering is a hard constraint (proxy image before gem `MINIMUM_VERSION` bump) — never delegate `script/release-dash` or tag pushes to an agent unsupervised. See `.claude/rules/upstream-sync.md` for the sync/release runbook and `../kamal/CLAUDE.md` for the gem-side contract.
