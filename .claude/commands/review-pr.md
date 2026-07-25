---
description: Review a GitHub pull request against dash-proxy fork rules, Go idioms, and upstream-sync constraints
model: opus
argument-hint: "PR URL or number (e.g., 12 or https://github.com/mhenrixon/kamal-proxy/pull/12)"
allowed-tools: mcp__github__pull_request_read, mcp__github__pull_request_review_write, mcp__github__add_comment_to_pending_review, Bash(make test:*), Bash(make build:*), Bash(make lint:*), Bash(gofmt:*), Bash(go vet:*), Bash(git:*)
---

# PR Review

Review PR for fork-rule compliance, Go idioms, and pattern issues. Be concise.

## Workflow

1. Fetch PR details and diff via `mcp__github__pull_request_read`
2. Confirm base branch is `dash`, not `main` — anything targeting `main` is an instant blocker (see Fork Rules)
3. Categorize changed files (RPC/CLI boundary, server internals, cert managers, upstream-owned files)
4. Check for pattern violations
5. Run local verification (`make build`, `make test`, `gofmt -l`)
6. Output structured review

## Fork Rules (from CLAUDE.md — check every PR)

| Check | Violation = blocker |
|---|---|
| Base branch | Targets `main` instead of `dash` |
| Tag grammar (if PR touches release scripts/CI) | Three-segment `vX.Y.Z` instead of four-segment `vX.Y.Z.N` |
| `kamal-proxy` naming | Renames the module, binary, RPC service name, or socket path |
| Upstream-owned files | Edits `Dockerfile`, `Makefile`, or `script/release` outside a sync merge (`.claude/rules/upstream-sync.md` says these are always upstream's) |
| OCI label | Touches `docker-publish.yml` without preserving `org.opencontainers.image.title=kamal-proxy` |
| `:latest` deploys | Adds any path that resolves/deploys against `:latest` instead of a numeric tag |
| `go mod tidy` hygiene | `go.mod`/`go.sum` diff drops `go-acme/lego/v4` or looks hand-edited instead of tidy output |
| Version command | Adds a `version` subcommand or flag — there isn't one; the image tag IS the version |

## Pattern Violations to Check

```go
// WRONG -> RIGHT
Bare `go func(){...}()` with no recover      -> wrap in a helper that recovers + logs
Unbuffered channel close from multiple sites -> single owner closes; document who
sync.Mutex copied by value (struct passed)   -> pass by pointer; go vet should catch this
Ignoring context cancellation in RPC calls   -> respect ctx / net/rpc timeout on client
err != nil swallowed silently                -> return wrapped error (fmt.Errorf("...: %w", err))
Hardcoded socket/state paths                 -> use existing config (~/.config/kamal-proxy)
New cert manager duplicating renewal loop    -> extend CertificateRenewalManager, don't fork it
Test file with no table-driven cases         -> prefer table-driven tests per Go convention
Exported symbol with no doc comment          -> add one if it crosses a package boundary
Direct target dial bypassing LoadBalancer    -> route through LoadBalancer.StartRequest
```

## Output Format

```
## Files Requiring Manual Review

| File | Reason |
|------|--------|
| internal/server/load_balancer.go | Target selection logic, verify race safety |
| internal/server/san_cert_manager.go | Cert issuance path, check renewal wiring |

## Critical Issues

- `internal/server/router.go:112` - Mutex held across RPC call, potential deadlock
- `internal/cmd/deploy.go:40` - Error from RPC client dropped, not wrapped

## Fork Compliance

- [ ] Targets `dash`, not `main`
- [ ] No `kamal-proxy` renames (module/binary/RPC/socket)
- [ ] No edits to Dockerfile/Makefile/script/release outside a sync merge
- [ ] Tag/version references are four-segment if touched
- [ ] `go mod tidy` clean, `go-acme/lego/v4` intact

## Suggestions (non-blocking)

- Consider table-driven tests for the new cert path

## Verdict

**Request Changes** - Fix mutex scope before merge
```

## Tools

```
mcp__github__pull_request_read
  method: "get"        -> PR details
  method: "get_diff"   -> Changes
  method: "get_files"  -> File list
  method: "get_status" -> CI status

make build              -> Compile bin/kamal-proxy
make test               -> go test ./...
gofmt -l internal/ cmd/ -> Must be empty; CI enforces this
go vet ./...            -> Catch mutex-copy and other static issues
make lint                -> golangci-lint (not installed locally; CI runs it — skip if unavailable, note in review)
```

## Cross-References

- `CLAUDE.md` — Critical Rules, architecture layers, branch map
- `.claude/rules/upstream-sync.md` — conflict playbook, release procedure
- `ROADMAP.md` — check whether the PR maps to a listed roadmap item or is unplanned scope
