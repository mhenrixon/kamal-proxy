---
description: "Use when a PR needs full review — fixes CI failures first, then addresses unresolved review comments. Run failures first because comment fixes trigger new CI runs that obscure the original failures."
model: opus
argument-hint: "PR number (e.g., 156 or #156)"
allowed-tools: Bash(gh pr list:*), Bash(gh pr view:*), Bash(gh pr checks:*), Bash(gh pr diff:*), Bash(gh pr comment:*), Bash(gh api:*), Bash(gh run view:*), Bash(git log:*), Bash(git blame:*), Bash(git diff:*), Bash(git push:*), Bash(git commit:*), Bash(git add:*), Bash(gofmt:*), Bash(go test:*), Bash(make test:*), Bash(make build:*), Read, Write, Edit, Glob, Grep, Agent
---

# Review GitHub PR (full pass): $ARGUMENTS

You are running a full review pass on a **dash-proxy** (`mhenrixon/kamal-proxy`) pull request. The pass has two phases that MUST run in this order:

1. **Phase A: CI failures** — fix anything red before touching review comments.
2. **Phase B: review comments** — only after Phase A leaves CI green (or pending green after a push).

## Why this order matters

If you fix review comments first, every commit pushes a new CI run. By the time the review-comment fixes finish, the original failure logs are buried under new pipeline runs. Symptoms:

- The `go test ./...` failure log you needed to read is now from a stale run; the latest run is still in progress on top of your unrelated comment fixes.
- A review-comment fix accidentally repairs the CI failure as a side effect, and you lose the chance to verify the failure was real.
- A review-comment fix accidentally INTRODUCES a CI failure, and you can't tell whether the new failure was pre-existing or your fault.

Failures-first eliminates this confusion. CI is either green or red on a known commit; the review-comment fixes layer cleanly on top.

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

After both phases complete, report:

1. **Phase A summary**: which CI failures were diagnosed and fixed. Note the commit SHAs for the fixes.
2. **Phase B summary**: which review comments were accepted (with commit SHAs), which were pushed back on (with reasoning), and the final unresolved-thread count (should be 0).
3. **Outstanding work**: anything that still needs attention — e.g., CI was pending at the end of Phase B and the user should verify the latest run after the comment fixes; or the PR is ready for `make docker` smoke-testing before merge to `dash`.

---

## Important Notes

- **Do not interleave the phases.** Don't fix a CI failure, then a review comment, then another CI failure. The whole point of this command is the strict ordering.
- **A new CI failure emerging during Phase B** (e.g., a comment fix breaks `go test ./...`) means looping back to Phase A — fix the new failure before continuing comment work. This is the only allowed reverse direction.
- **If the PR has no failures AND no unresolved comments**, report "PR is clean" and stop.
- **If `$ARGUMENTS` is the same as the current open PR**, the two child slash commands will see the same PR. They share state through the git branch and the GitHub API, not through any in-process variable.
- **Don't re-implement the child slash commands' logic**. Invoke them and let them do their work. This command is the orchestrator.
- **Never fix by disabling** — no `//nolint`, no skipped tests, no `gofmt`-fighting. Fix the root cause; see `.claude/rules/testing.md` and `.claude/rules/git-workflow.md`.
