---
description: "Use when a PR needs full review — resolves merge conflicts with the base first, then fixes CI failures, then addresses unresolved review comments. Conflicts first so CI diagnoses the post-merge reality; failures before comments because comment fixes trigger new CI runs that obscure the original failures."
model: opus
argument-hint: "PR number (e.g., 156 or #156)"
allowed-tools: Bash(gh pr list:*), Bash(gh pr view:*), Bash(gh pr checks:*), Bash(gh pr checkout:*), Bash(gh pr diff:*), Bash(gh pr comment:*), Bash(gh api:*), Bash(gh run view:*), Bash(git log:*), Bash(git blame:*), Bash(git diff:*), Bash(git status:*), Bash(git switch:*), Bash(git fetch:*), Bash(git merge:*), Bash(git merge-tree:*), Bash(git rev-parse:*), Bash(git push:*), Bash(git commit:*), Bash(git add:*), Bash(gofmt:*), Bash(go test:*), Bash(go build:*), Bash(go mod:*), Bash(make test:*), Bash(make build:*), Read, Write, Edit, Glob, Grep, Agent
---

# Review GitHub PR (full pass): $ARGUMENTS

You are running a full review pass on a **dash-proxy** (`mhenrixon/kamal-proxy`) pull request. The pass has three phases that MUST run in this order:

1. **Phase A0: merge conflicts** — bring the branch up to date with its base and resolve any conflicts before anything else.
2. **Phase A: CI failures** — fix anything red before touching review comments.
3. **Phase B: review comments** — only after Phase A leaves CI green (or pending green after a push).

## Why this order matters

**Conflicts before failures**: CI results only matter for the code that will actually merge. On a conflicted (or stale) branch you'd diagnose failures against a base that no longer exists — and the conflict resolution itself changes code, invalidating the run you just fixed. Resolving conflicts first means Phase A reads CI for the post-merge reality, and you spend exactly one extra CI cycle instead of two.

**Failures before comments**: if you fix review comments first, every commit pushes a new CI run. By the time the review-comment fixes finish, the original failure logs are buried under new pipeline runs. Symptoms:

- The `go test ./...` failure log you needed to read is now from a stale run; the latest run is still in progress on top of your unrelated comment fixes.
- A review-comment fix accidentally repairs the CI failure as a side effect, and you lose the chance to verify the failure was real.
- A review-comment fix accidentally INTRODUCES a CI failure, and you can't tell whether the new failure was pre-existing or your fault.

Conflicts-first, then failures-first eliminates this confusion. CI is either green or red on a known commit against the current base; the review-comment fixes layer cleanly on top.

## Fork context — read before touching anything

This is a maintained fork, not a normal repo. Before either phase, ground yourself in:

- `CLAUDE.md` — Critical Rules: `kamal-proxy` module/binary/RPC/socket naming is load-bearing, `main` is fast-forward-only (never commit to it), tags are four-segment `vX.Y.Z.N`, no `git push --tags`.
- `.claude/rules/git-workflow.md` — commit message format, branch model, pre-commit checklist.
- `.claude/rules/upstream-sync.md` — merge conflict playbook if the PR touches `internal/cmd/run.go`, `internal/server/config.go`, `internal/server/router.go`, or `internal/server/service.go` (the two cert branches' overlap zone).
- `.claude/rules/testing.md` — 100% coverage floor for Router, LoadBalancer, SANCertManager, cert registry, RPC commands.

**The PR must target `dash`, not `main`.** If `gh pr view` shows a base of `main`, stop and flag it — that branch only accepts fast-forward merges from upstream.

## Phase 0: Determine the PR Number

The user may provide a PR number as `$ARGUMENTS`. Parse it flexibly:

- `PR156`, `PR 156`, `pr156` → PR 156
- `156` → PR 156
- `#156` → PR 156
- Empty/blank → auto-detect from current branch

**If no PR number is provided**, detect it automatically:

```bash
gh pr list --repo mhenrixon/kamal-proxy --author=@me --head="$(git branch --show-current)" --state=open --json number,title
```

If exactly one open PR exists for the current branch, use it. If none or multiple, ask the user.

Once you have the PR number, confirm it and its base branch:

```bash
gh pr view <PR_NUMBER> --repo mhenrixon/kamal-proxy --json title,state,url,baseRefName
```

---

## Phase A0: Merge conflicts

Check whether the branch merges cleanly into its base:

```bash
gh pr view <PR_NUMBER> --repo mhenrixon/kamal-proxy --json mergeable,mergeStateStatus,baseRefName
```

| `mergeable` | Action |
|-------------|--------|
| `MERGEABLE` | Skip to Phase A. |
| `UNKNOWN` | GitHub is recomputing (common right after pushes, and it can stay UNKNOWN for minutes). Don't poll it — verify **locally**, against the PR's actual head (NOT `HEAD`, which may be some other checked-out branch): `git fetch origin <base>` and `git fetch origin pull/<PR>/head`, verify both refs resolve (`git rev-parse --verify origin/<base>^{commit}` and `git rev-parse --verify FETCH_HEAD^{commit}` — a bad ref also exits 1 from merge-tree, so exit code alone can't be trusted), then `git merge-tree --write-tree --name-only origin/<base> FETCH_HEAD`. Clean exit → no conflicts, skip to Phase A. Exit 1 **with conflict output** → resolve below (the `--name-only` file list is your work list). |
| `CONFLICTING` | Resolve, below. |

### Which branch do you merge? (fork-specific — decide BEFORE merging)

The branch model (`.claude/rules/git-workflow.md`) forbids merging `dash` into an upstream-PR-able feature branch — fork-only cert code would contaminate it. So:

1. **First try `git merge origin/main`** — the sanctioned forward merge. Most conflicts against `dash` come from upstream code that reached `dash` via `main`; merging `main` forward resolves them without contaminating the branch. Re-check mergeability against `dash` afterwards.
2. **Still conflicting?** The overlap is fork-only code on `dash` (typically the cert overlap zone: `internal/cmd/run.go`, `internal/server/config.go`, `internal/server/router.go`, `internal/server/service.go`). If the branch is fork-internal (never intended for a basecamp PR), merging `origin/dash` is acceptable. If the branch is meant to stay upstream-PR-able, **stop and ask the user** — merging `dash` would be irreversible contamination.

Note `git rerere` is enabled: previously-seen conflicts auto-replay their resolutions — review what rerere staged before trusting it.

### Resolution procedure

1. Check out the PR's branch (`gh pr checkout <PR_NUMBER>`) with a clean tree (`git status`). Stash nothing — if the tree is dirty, stop and ask the user.
2. `git fetch origin <base>` then **`git merge`** the branch chosen above — MERGE, never rebase. The branch is shared (it has a PR); a rebase would require a force-push, which `.claude/rules/git-workflow.md` forbids on shared branches.
3. Resolve every conflicted file **semantically** — read both sides and produce the version that preserves BOTH changes' intent. Never blanket `--ours`/`--theirs` a source file. Repo-specific rules (the authoritative playbook is `.claude/rules/upstream-sync.md`):
   - **`go.mod` / `go.sum`**: never hand-merge `go.sum`. Resolve `go.mod` semantically (union of requires; take the incoming (merged-in) branch's toolchain + dep versions — main's on a main-forward merge — keep `go-acme/lego/v4`), then run `go mod tidy` to regenerate `go.sum`.
   - **The cert overlap zone** (`internal/cmd/run.go`, `internal/server/config.go`, `internal/server/router.go`, `internal/server/service.go`): follow the union rules in `.claude/rules/upstream-sync.md`'s conflict playbook — e.g. register `--acme-email`/`--acme-directory` ONCE (pflag panics on duplicates), keep both cert init blocks, keep both `sanCertManager` and `certRegistry`.
   - **`Dockerfile`, `Makefile`, `script/release`**: always upstream's/the base's — the fork never edits them.
   - **`.github/workflows/*.yml`**: preserve the SHA-pinned-action-with-version-comment pattern (e.g. `actions/checkout@34e11487… # v4.3.1`) — actionlint/zizmor gate these in CI.
4. Run the verification gates BEFORE pushing the merge:
   ```bash
   gofmt -l internal/ cmd/     # must print nothing
   make build
   make test
   # golangci-lint (make lint) is CI-only — not runnable locally; expect CI to be the verifier
   ```
5. Commit the merge (keep git's standard merge-commit message; add a body line naming any non-obvious resolution choice) and `git push` — a merge commit never needs force.

### Phase A0 exit criteria

- The PR reports `MERGEABLE` (or the local `git merge-tree` check is clean), AND the merge commit (if one was needed) is pushed.
- If the merge produced changes, CI is now re-running — that's expected; Phase A reads the fresh run.
- If a conflict cannot be resolved with confidence (both sides rewrote the same logic and the correct combination isn't decidable from the code, or resolving requires merging `dash` into an upstream-PR-able branch), **stop and ask the user** — a guessed resolution that compiles is worse than a question.

---

## Phase A: Run `/github-review-failures`

Invoke the existing `/github-review-failures` slash command with the same `$ARGUMENTS` value. Its purpose: fix every failing CI check, push, leave the branch in a state where CI is either green or running-pending-toward-green.

Follow that command's full process. The slash command is at `.claude/commands/github-review-failures.md`. Its workflow:

1. Identify failing checks via `gh pr checks <PR>` — expect `build`, `test`, `golangci-lint`, `actionlint`/`zizmor` from `ci.yml`.
2. Fetch failure logs via `gh run view <RUN_ID> --job=<JOB_ID> --log-failed`.
3. Diagnose root cause for each — `gofmt` drift, `go test ./...` failure, `golangci-lint` finding (CI-only, not runnable locally), or a build break.
4. Fix locally — `gofmt -l internal/ cmd/` first (fast, deterministic, the one local proxy for `golangci-lint`), then `make test`, then `make build` issues.
5. Verify locally before commit (`gofmt -l internal/ cmd/` must be empty, `make test` green, `make build` clean).
6. Commit + push + report which checks are now running.

### Phase A exit criteria

Before moving to Phase B, one of these must be true:

- All CI checks are green on the latest pushed commit. OR
- All CI checks are pending (running) on the latest pushed commit, AND no checks failed in the most recent completed run on this commit. OR
- A persistent CI failure exists that is **not caused by changes on this branch** (e.g., a flaky test on `dash`, an `actionlint`/`zizmor` finding pre-existing on the base branch). Report this explicitly and proceed to Phase B with the caveat noted.

If failures persist on this branch's changes, **do NOT proceed to Phase B**. Report what's still failing, what's been tried, and ask the user how to proceed.

---

## Phase B: Run `/github-review-comments`

Once Phase A's exit criteria are met, invoke `/github-review-comments` with the same `$ARGUMENTS`. Its purpose: address every unresolved review thread on the PR, push fixes, reply with commit SHAs, and resolve the threads.

The slash command is at `.claude/commands/github-review-comments.md`. Its workflow:

1. Fetch all unresolved review threads via the GitHub GraphQL API (`repo: kamal-proxy`, `owner: mhenrixon`).
2. Read and categorise each comment (valid fix / invalid suggestion / unclear) against `CLAUDE.md` Critical Rules and the architecture layers — a suggestion to rename `kamal-proxy`, edit `Dockerfile`/`Makefile`/`script/release-dash`, or commit to `main` is an automatic reject, not a judgment call.
3. Implement accepted fixes; verify locally (`make test`, `gofmt -l internal/ cmd/`).
4. Commit all fixes together with a clear conventional-commit message; push.
5. Reply to every thread with the commit SHA (for accepted fixes) or technical reasoning (for rejections).
6. Resolve each thread via the GraphQL `resolveReviewThread` mutation.
7. Verify no unresolved threads remain.

### Phase B exit criteria

- All unresolved review threads have been replied to and resolved (or the user has explicitly approved leaving a specific thread open).
- The branch has been pushed with all accepted fixes.

---

## Phase C: Final report

Before reporting, re-check mergeability once more (`gh pr view <PR> --repo mhenrixon/kamal-proxy --json mergeable`, or the local `git merge-tree` check if UNKNOWN) — the base can move underneath a long pass. If a NEW conflict appeared, loop back to Phase A0.

After all phases complete, report:

1. **Phase A0 summary**: whether the branch was conflicted, which files conflicted, how each was resolved (which branch was merged forward, and the merge commit SHA) — or "clean merge, no action".
2. **Phase A summary**: which CI failures were diagnosed and fixed. Note the commit SHAs for the fixes.
3. **Phase B summary**: which review comments were accepted (with commit SHAs), which were pushed back on (with reasoning), and the final unresolved-thread count (should be 0).
4. **End state**: final mergeability + CI status on the latest commit.
5. **Outstanding work**: anything that still needs attention — e.g., CI was pending at the end of Phase B and the user should verify the latest run after the comment fixes; or the PR is ready for `make docker` smoke-testing before merge to `dash`.

---

## Important Notes

- **Do not interleave the phases.** Don't fix a CI failure, then a review comment, then another CI failure. The whole point of this command is the strict ordering.
- **A new CI failure emerging during Phase B** (e.g., a comment fix breaks `go test ./...`) means looping back to Phase A — fix the new failure before continuing comment work. Likewise, **a new conflict appearing mid-pass** (the base moved) means looping back to Phase A0. These loop-backs are the only allowed reverse directions.
- **If the PR is already merged**, there is nothing to review — report that and stop. (A stale `$ARGUMENTS` or a just-merged PR shows up as `state: MERGED` in Phase 0's confirm step.)
- **If the PR merges cleanly, has no failures AND no unresolved comments**, report "PR is clean" and stop.
- **If `$ARGUMENTS` is the same as the current open PR**, the two child slash commands will see the same PR. They share state through the git branch and the GitHub API, not through any in-process variable.
- **Don't re-implement the child slash commands' logic**. Invoke them and let them do their work. This command is the orchestrator.
- **Never fix by disabling** — no `//nolint`, no skipped tests, no `gofmt`-fighting. Fix the root cause; see `.claude/rules/testing.md` and `.claude/rules/git-workflow.md`.
