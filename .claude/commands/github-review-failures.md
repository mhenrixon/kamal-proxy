---
description: "Use when CI checks are failing on a PR — fetches failure logs, diagnoses root causes, implements fixes, and pushes until CI is green."
model: sonnet
argument-hint: "PR number (e.g., 41 or #41)"
allowed-tools: Bash(gh pr view:*), Bash(gh pr checks:*), Bash(gh pr diff:*), Bash(gh api:*), Bash(gh run view:*), Bash(git log:*), Bash(git diff:*), Bash(git push:*), Bash(git commit:*), Bash(git add:*), Bash(go test:*), Bash(go build:*), Bash(go vet:*), Bash(gofmt:*), Bash(golangci-lint:*), Bash(make build:*), Bash(make test:*), Bash(make lint:*), Read, Write, Edit, Glob, Grep, Agent
---

# Fix GitHub CI Failures: $ARGUMENTS

You are diagnosing and fixing CI failures on a `mhenrixon/kamal-proxy` pull request. Work systematically: identify failures, read logs, diagnose root causes, fix locally, verify, push.

**Fork boundary first**: confirm the PR's base branch is `dash` (or a feature branch merging into it), never `main` — `main` is a fast-forward-only mirror of upstream and this command must never push a fix there. See `.claude/rules/upstream-sync.md`.

## Phase 0: Determine the PR Number

The user may provide a PR number as `$ARGUMENTS`. Parse it flexibly:

- `PR41`, `PR 41`, `pr41` -> PR 41
- `41` -> PR 41
- `#41` -> PR 41
- Empty/blank -> auto-detect from current branch

**If no PR number is provided**, detect it automatically:

```bash
gh pr list --repo mhenrixon/kamal-proxy --author=@me --head="$(git branch --show-current)" --state=open --json number,title
```

If exactly one open PR exists for the current branch, use it. If none or multiple, ask the user.

Once you have the PR number, confirm it and its base branch:

```bash
gh pr view <PR_NUMBER> --repo mhenrixon/kamal-proxy --json title,state,url,baseRefName,mergeable
```

**Pre-flight: merge conflicts (detection only).** If `mergeable` is `CONFLICTING`, STOP — do not diagnose CI on a conflicted branch (the merge itself may fix or cause the failures). Report the conflict and hand off to `/github-review-pr`, whose Phase A0 owns the resolution runbook (including this fork's merge-forward rules) — this command's toolset deliberately does not include the merge machinery. If `mergeable` is `UNKNOWN`, note it and proceed: the orchestrator resolves the ambiguity; a standalone run shouldn't block on GitHub's recompute.

---

## Phase 1: Identify Failing Checks

```bash
gh pr checks <PR_NUMBER> --repo mhenrixon/kamal-proxy
```

`ci.yml` runs two jobs per push/PR against `main` and `dash`; `docker-publish.yml` only fires on tag push, so it is never a PR check.

| Check | Job | What it runs | How to get logs |
|---|---|---|---|
| GitHub Actions audit | `lint-actions` | actionlint + zizmor over `.github/workflows/*.yml` | `gh run view <RUN_ID> --job=<JOB_ID> --log-failed` |
| Build | `build` (build step) | `make build` (`CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...`) | `gh run view <RUN_ID> --job=<JOB_ID> --log-failed` |
| Test | `build` (test step) | `make test` (`go test ./...`) | `gh run view <RUN_ID> --job=<JOB_ID> --log-failed` |
| Lint | `build` (lint step) | `make lint` (`golangci-lint run`, v2.11.3 pinned in CI) | `gh run view <RUN_ID> --job=<JOB_ID> --log-failed` |

Extract the run ID and job IDs from the check URLs. The URL format is:
`https://github.com/mhenrixon/kamal-proxy/actions/runs/<RUN_ID>/job/<JOB_ID>`

If all checks pass or are pending, report that and stop.

---

## Phase 2: Fetch Failure Logs

For each failing check, get the logs:

```bash
# Get the failed job logs (condensed output)
gh run view <RUN_ID> --job=<JOB_ID> --log-failed
```

If `--log-failed` output is too large or unclear, try:

```bash
# Full log for a specific job
gh run view <RUN_ID> --job=<JOB_ID> --log 2>&1 | tail -100
```

---

## Phase 3: Diagnose Each Failure

For each failure, determine the root cause:

### Lint Failures (`golangci-lint`)

**golangci-lint is not installed locally** — you cannot reproduce this check by running `make lint` in this sandbox. Diagnose from the CI log alone:
- Linter name, file:line, and message are printed per finding
- `gofmt` issues surface here too — those you *can* fix and verify locally (see below)

### Actions Audit Failures (`actionlint` / `zizmor`)

Look for:
- `actionlint`: YAML/expression syntax errors in `.github/workflows/*.yml`
- `zizmor`: workflow security findings (unpinned actions, injectable `${{ }}` expressions, excess `permissions:`). Workflow files pin actions by SHA with a version comment (e.g. `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1`) — preserve that pattern in any fix.

### Build Failures (`make build`)

Look for:
- Compile errors: type mismatches, unresolved imports, unused variables/imports (Go treats these as hard errors)
- Module errors: run `go mod tidy` and check `go.mod`/`go.sum` are in sync — the fork carries `go-acme/lego/v4` on top of upstream's dep graph; don't drop it while tidying

### Test Failures (`go test ./...`)

Look for:
- Test name and package path
- Error class/message and relevant backtrace lines (ignore `testing` framework noise)
- Whether it's a genuine regression vs an environment-only failure

**Key patterns**:
- `undefined: X` / `X.Y undefined (type *Z has no field or method Y)` -> API drift, check recent upstream merges (`git log --oneline main..dash -- internal/`)
- `panic: runtime error` -> nil deref or index bug, read the failing test's setup
- `expected X, got Y` -> logic bug or the test needs updating for a real behavior change
- Cert/ACME test failures -> check `internal/server/acme/` and `san_cert_manager.go` first; these are the fork's own code, most likely to regress on a `main` merge

---

## Phase 4: Fix Locally

For each diagnosed failure:

1. **Read the relevant file** to understand context before fixing
2. **Make the fix** — edit the file
3. **Verify locally** before committing:

```bash
# Formatting (CI enforces this; golangci-lint itself you cannot run locally)
gofmt -l internal/ cmd/          # must print nothing

# Compile
go build ./...

# Targeted test
go test ./internal/server/... -run TestName -v

# Full validation
make test
```

### Fix Priority Order

1. **`gofmt` / build errors** first (fast, deterministic, verifiable locally)
2. **Test failures** second (may require understanding the code change)
3. **Actions-audit findings** third (usually a pin/permissions tweak in workflow YAML)
4. **golangci-lint findings** last, and flag them for a follow-up CI run since you cannot verify locally before pushing

---

## Phase 5: Commit and Push

```bash
git add <specific_files>
git commit -m "$(cat <<'EOF'
fix(ci): <brief description of what was fixed>

- Fix 1 description
- Fix 2 description
EOF
)"
git push
```

Never push directly to `main`. If the PR's base is `main`, stop and tell the user — that branch only fast-forwards from upstream.

---

## Phase 6: Verify

After pushing, check if CI has been re-triggered:

```bash
gh pr checks <PR_NUMBER> --repo mhenrixon/kamal-proxy
```

If there are still pending checks, report which checks are running and what was fixed. Do NOT poll in a loop — report the status and let the user know.

If you can identify that certain failures will persist for environmental reasons, flag that explicitly rather than chasing them:

| Known flaky/env failure | Why |
|---|---|
| golangci-lint findings that can't be reproduced locally | linter isn't installed in this sandbox; CI is the only source of truth, so expect at least one extra push/verify cycle |
| Integration-style tests exercising a published proxy image | need `ghcr.io/mhenrixon/kamal-proxy` at a real tag; nothing to fix if the image itself hasn't been released yet — see release ordering in `../kamal/.claude/rules/upstream-sync.md` |
| Architecture-dependent test failures surfaced only on `dash`'s multi-arch build | check whether the failure is amd64/arm64-specific before "fixing" logic that's actually fine on the developer's arch |

---

## Important Notes

- **Read before fixing** — always read the actual failing code before attempting a fix
- **Fix the root cause** — don't add `//nolint` to bypass lint; fix the actual issue
- **Don't fix unrelated failures** — if a test was already failing on `dash`, note it but don't fix it in this PR
- **Respect `CLAUDE.md`'s Never Do list** — no renaming `kamal-proxy` (module/binary/RPC/socket), no three-segment `v*` tags, no touching `Dockerfile`/`Makefile`/`script/release-dash` (those stay upstream's on merge, per `.claude/rules/upstream-sync.md`)
- **Flaky tests** — if a test passes locally but fails in CI, note it as potentially flaky rather than adding workarounds
- **Don't retry CI blindly** — diagnose first, fix, then push. Each push triggers a full CI run.

Now begin by determining the PR number and fetching the failing checks.
