---
description: "Executes full autonomous engineering workflow with verification. Use when implementing complete features, tackling GitHub issues, or running end-to-end development cycles on the dash-proxy fork."
model: opus
argument-hint: "GitHub issue number/URL or feature description"
allowed-tools: Bash(gh issue view:*), Bash(gh search:*), Bash(gh issue list:*), Bash(gh pr create:*), Bash(gh pr view:*), Bash(make:*), Bash(go test:*), Bash(gofmt:*), Bash(go vet:*), Bash(git:*), Read, Write, Edit, Glob, Grep, Agent
---

# LFG - Full Autonomous Workflow

Execute a complete engineering workflow with verification at each phase, respecting this repo's fork branch model.

## Phase 0: Branch Setup

**BEFORE any other work, prepare the git branch. This is a fork — `main` is a fast-forward-only mirror of `basecamp/kamal-proxy`. NEVER commit to it.**

1. Check the current branch: `git branch --show-current`
2. If NOT on `main`, switch: `git checkout main`
3. Sync with upstream (do not assume `origin/main` is current): `git fetch upstream --tags --prune && git merge --ff-only upstream/main && git push origin main`
4. Create feature branch **off `main`** (keeps it upstream-PR-able): `git checkout -b feature/{description}` (or `fix/{description}`, `issue-{number}-{brief-description}`)
5. The branch merges **forward** into `dash` at PR time — never rebase it once pushed. See `.claude/rules/git-workflow.md` and `.claude/rules/upstream-sync.md`.

---

## Phase 1: Understand

### Step 1: Gather Requirements

If `$ARGUMENTS` is a GitHub issue number or URL:

```bash
gh issue view <number> --json title,body,labels,assignees,comments
```

If `$ARGUMENTS` is a description, use it directly.

### Step 2: Define Acceptance Criteria

**MANDATORY:** Write explicit acceptance criteria:

- **GIVEN** [context/setup]
- **WHEN** [action taken]
- **THEN** [expected outcome]

You MUST NOT proceed until you can articulate these clearly.

### Step 3: Comprehension Gate

Before proceeding, you must:

1. State the problem/feature in one sentence
2. Explain WHY this is needed (business context — check `ROADMAP.md` for an existing anchor before inventing one)
3. List what will change from the user's perspective (CLI flag? RPC arg? deploy behavior?)
4. Identify edge cases not explicitly mentioned
5. Explain the data flow or code path involved, in terms of this repo's layers: `cmd/kamal-proxy` → `internal/cmd` (cobra CLI + RPC client) → unix socket RPC → `internal/server` (Router, Service, LoadBalancer, cert managers)

If you cannot complete ALL five items, investigate further.

### Step 4: Create Task List

Create a TaskCreate todo list with specific implementation steps.

---

## Phase 2: Explore

1. Find related files (Glob/Grep or Explore agent)
2. Read existing patterns in similar features — e.g. how `ServiceOptions` (`internal/server/service.go:82`) or `TargetOptions` (`internal/server/target.go:65`) added a prior knob
3. Understand dependencies and integration points across the three layers
4. Check existing test coverage (`*_test.go` next to the file you're touching)
5. If touching RPC surface, review `internal/server/commands.go` (RPC name registration + arg structs) and the ~9 client call sites in `internal/cmd/`
6. If touching persisted config, check `Service.MarshalJSON`/`UnmarshalJSON` (`internal/server/service.go:273/294`) for round-trip/default-safety against old state files
7. Check `ROADMAP.md` for a code anchor already scoped for this work

---

## Phase 3: Plan

1. List files to modify with specific changes
2. List new files to create with purpose
3. Identify flag/RPC changes needed: `internal/cmd/{deploy,run}.go` flags → `server.DeployArgs`/`server.GlobalConfig` → RPC arg structs in `internal/server/commands.go`
4. Plan test coverage (TDD: tests FIRST) — table-driven `go test`, `testify/assert`, follow patterns in existing `*_test.go`
5. Update task list with implementation steps
6. Consider backwards compatibility: old state files (JSON-persisted `ServiceOptions`/`TargetOptions`) must still load; never rename module/binary/RPC/socket away from `kamal-proxy`

---

## Phase 4: Implement (TDD)

For each logical unit:

### 4.1: Write Failing Test First

Create a test that demonstrates the expected behavior. Run it to confirm it FAILS:

```bash
go test ./internal/server/... -run TestYourNewBehavior -v
```

### 4.2: Implement Minimum Code

Write the MINIMUM code to make the test pass. Follow project patterns:

| Never Do | Always Do |
|----------|-----------|
| Rename module/binary/RPC service/socket away from `kamal-proxy` | Keep it load-bearing-identical (Dockerfile, kamal gem `exec` calls, RPC registration all depend on it) |
| Hand-roll RPC dialing | Reuse the `net/rpc` client pattern in `internal/cmd/util.go` |
| Add a knob only to `ServiceOptions` and forget the flag | Wire flag (`internal/cmd/deploy.go` or `run.go`) → arg struct (`commands.go`) → `ServiceOptions`/`TargetOptions`/`DeploymentOptions` |
| Skip JSON round-trip for new persisted fields | Update `MarshalJSON`/`UnmarshalJSON` and default old state files safely |
| Ignore the streaming/SSE bypass when touching response middleware | Check `response_buffer_middleware.go:86` bypass logic first |
| Edit `Dockerfile`, `Makefile`, or `script/release*` casually | These stay upstream's on `main`; fork-only changes belong on `dash`/feature branches per `.claude/rules/upstream-sync.md` |

### 4.3: Refactor

Once green, refactor while keeping tests passing.

### 4.4: Validate

```bash
gofmt -l internal/ cmd/      # must print nothing — CI enforces formatting
go vet ./...
```

`make lint` (golangci-lint) is CI-only, not installed locally — `gofmt -l` is the local stand-in, don't skip it.

### 4.5: Repeat

Move to next logical unit. Mark task items complete.

---

## Phase 5: Deep Root Cause Analysis (Bug Fixes Only)

**If this is a bug fix, apply deep investigation before implementing:**

### Trace the Request Lifecycle

For the request/connection causing the issue:
- Where did it enter — `internal/server/server.go` listener, then `Router`, then `Service`, then `LoadBalancer.StartRequest` (`load_balancer.go:174`), then `Target.createProxyHandler` (`target.go:293`)?
- What timeout/deadline applies at that point (`ResponseHeaderTimeout` at `target.go:302`, health check intervals, cert renewal windows)?
- What ASSUMPTIONS does the code make at the failure point?
- Which assumption was violated, and WHY?

### Use Git History

```bash
git log --oneline -20 <file>
git blame <file>
```

- When was the code written — upstream, or one of the fork's cert branches (`san-certificate-batching`, `wildcard-certs`)?
- Has a later `main` merge changed an assumption the fork code relied on? Check `.claude/rules/upstream-sync.md`'s conflict playbook for this file.

### Map All Callers

Don't just look at the method that failed:
- Use Grep to find all call sites (RPC client in `internal/cmd/`, RPC server in `internal/server/commands.go`, direct calls within `internal/server/`)
- Different contexts (CLI deploy path vs RPC server vs test harness in `internal/server/testing.go`)?
- Does the error only happen in ONE context? Why?

### Five Whys

Keep asking WHY until you reach a meaningful fix point:

1. Error: X happened -> Why?
2. Because Y -> Why was Y in that state?
3. Because Z -> Why wasn't Z prevented?
4. Because no check existed -> Why not?
5. **THIS** is where the fix belongs

### Fix Location Principle

The best fix is usually NOT where the error is raised:
- Nil target in load balancer -> fix in `Service` that should never register a nil target
- Certificate not found -> fix in the manager that should ensure provisioning before serving
- Race condition -> fix at the state-file / mutex boundary, not with a retry loop
- RPC arg mismatch -> fix the arg struct/version contract in `commands.go`, not the symptom at the call site

**Ask: "Where is the EARLIEST point I could prevent this error?" Fix there.**

### Unacceptable Superficial Fixes -- DO NOT DO THESE

- `if err != nil { return nil }` swallowing an error without understanding why it occurs
- Ignoring an error return (`_ = fn()`) to silence a failure path
- Nil-checking a pointer defensively without understanding why it could be nil
- Wrapping goroutines in blanket `recover()` to hide panics
- Increasing a timeout to mask a deadlock/race instead of fixing it

**These HIDE bugs. The root cause continues causing issues elsewhere.**

---

## Phase 6: Verify

**ALL of these must pass before committing:**

```bash
gofmt -l internal/ cmd/      # Formatting — must be empty
make test                    # go test ./...
go vet ./...
```

If you have `golangci-lint` installed locally, also run `make lint` — but its absence is not a blocker; CI runs it on `main` and `dash`.

### Solution Verification

Re-read the original requirements and verify:
- "If I were the requester, would I consider this fully resolved?"
- "Have I addressed the ROOT CAUSE, not just the symptom?"
- "Do my tests prove the issue is ACTUALLY fixed, not just suppressed?"
- "Does this maintain backwards compatibility with existing state files and the `kamal` gem's RPC/CLI expectations?"

---

## Phase 7: Commit & PR

### Commit

```bash
git add <specific_files>
git commit -m "$(cat <<'EOF'
feat(scope): brief description

## Summary
[What changed and why]

## Test Coverage
- TestX: validates requirement X
- TestY: validates edge case Y

## Verification
- [x] gofmt -l internal/ cmd/ clean
- [x] make test passes
EOF
)"
```

Scope = the package/feature area, e.g. `san-cert`, `wildcard-certs`, `router`, `rpc`. See `.claude/rules/git-workflow.md` for commit conventions.

### Push & PR

**PRs target `dash`, never `main`** — `main` only ever fast-forwards from upstream.

```bash
git push -u origin $(git branch --show-current)

gh pr create --base dash --title "feat(scope): brief description" --body "$(cat <<'EOF'
## Summary
- Key change 1 touching `internal/server/foo.go`
- Key change 2

Closes #<issue_number>

## Test plan
- [ ] Scenario 1
- [ ] Scenario 2
EOF
)"
```

**Markdown inside the quoted heredoc is literal — do not escape.** The single-quoted `<<'EOF'` delimiter disables shell expansion on the body, so:

- Write backticks as backticks: `` `foo` ``. Do NOT write `\`foo\``; that writes a literal backslash-backtick and breaks the code span.
- Write dollar signs as-is: `$HOME`. No escaping needed.
- Write backslashes as-is: `\n` stays `\n`.

The body is copied verbatim into the PR / commit message. If you would not type a backslash in a GitHub comment, do not type one in the heredoc.

If the body is long or contains many backticks / tables, prefer writing it to a temp file and passing `--body-file`:

```bash
cat > /tmp/pr-body.md << 'EOF'
## Summary
...any markdown...
EOF
gh pr create --base dash --title "..." --body-file /tmp/pr-body.md
rm /tmp/pr-body.md
```

The `--body-file` path avoids the double-layer of shell interpretation entirely and makes long PR bodies easier to read in the terminal buffer.

---

## Release (only if this workflow ends in a release)

Not part of the default flow — only after a PR is merged to `dash` and a release is explicitly requested. Full runbook: `.claude/rules/upstream-sync.md`.

```bash
git checkout dash
script/release-dash v0.9.2.1     # validates vX.Y.Z.N grammar, runs make test, tags, pushes the tag
# CI publishes ghcr.io/mhenrixon/kamal-proxy:v0.9.2.1 (+ :latest)
docker buildx imagetools inspect ghcr.io/mhenrixon/kamal-proxy:v0.9.2.1   # verify amd64+arm64
```

The image has no version command — the tag IS the version. Release the proxy **before** the `dash` gem; the gem's `MINIMUM_VERSION` must name an already-published tag.

---

## Verification Checklist

- [ ] All acceptance criteria met
- [ ] Tests written BEFORE implementation
- [ ] `gofmt -l internal/ cmd/` clean
- [ ] `make test` passes
- [ ] `go vet ./...` clean
- [ ] Backwards compatibility maintained (state files, RPC contract, `kamal-proxy` naming untouched)
- [ ] Branch rooted off `main`, PR opened against `dash`
- [ ] PR created with description

---

## Handoff

When complete:
- All phases executed
- Verification passed
- PR created against `dash` and linked

Now, execute this workflow for the provided issue or feature.
