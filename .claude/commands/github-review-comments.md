---
description: "Use when a PR has unresolved review comments that need responses -- evaluates each comment, implements valid fixes, pushes back on incorrect suggestions, and resolves all threads."
model: sonnet
argument-hint: "PR number (e.g., 123 or #123)"
allowed-tools: Bash(gh pr view:*), Bash(gh pr diff:*), Bash(gh pr comment:*), Bash(gh api:*), Bash(git log:*), Bash(git blame:*), Bash(git push:*), Bash(git commit:*), Bash(git add:*), Bash(make test:*), Bash(make lint:*), Bash(gofmt:*), Bash(go test:*), Bash(go vet:*), Read, Write, Edit, Glob, Grep, Agent
---

# Review GitHub PR Comments: $ARGUMENTS

You are reviewing and responding to all unresolved review comments on a GitHub pull request against `mhenrixon/kamal-proxy`. Apply technical rigour -- evaluate each comment against the actual codebase before accepting or rejecting it.

**Fork context first.** This repo is a fork of `basecamp/kamal-proxy`, not a normal project. Before evaluating anything, know:

- PRs target `dash`, never `main` -- `main` is a fast-forward-only mirror of upstream and never receives commits
- `kamal-proxy` naming (module, binary, RPC service, socket) is load-bearing -- see `CLAUDE.md` Critical Rules #1; never accept a rename suggestion
- Tags are four-segment `vX.Y.Z.N`, never plain `vX.Y.Z` -- see `.claude/rules/git-workflow.md`
- Full sync/branch rules: `.claude/rules/upstream-sync.md`, `.claude/rules/git-workflow.md`

---

## Phase 0: Determine the PR Number

The user may provide a PR number as `$ARGUMENTS`. Parse it flexibly:

- `PR123`, `PR 123`, `pr123` -> PR 123
- `123` -> PR 123
- `#123` -> PR 123
- Empty/blank -> auto-detect from current branch

**If no PR number is provided**, detect it automatically:

```bash
gh pr list --author=@me --head="$(git branch --show-current)" --state=open --json number,title
```

If exactly one open PR exists for the current branch, use it. If none or multiple, ask the user.

Once you have the PR number, confirm it -- and confirm the base branch is `dash`, not `main`:

```bash
gh pr view <PR_NUMBER> --json title,state,url,baseRefName
```

If `baseRefName` is `main`, stop and flag it -- that PR is misdirected (see Branch Model above); don't process review comments on it as if it were normal.

---

## Phase 1: Fetch All Unresolved Review Comments

Retrieve all review comments and identify unresolved ones:

```bash
# Get all review comments (not resolved)
gh api "repos/mhenrixon/kamal-proxy/pulls/<PR_NUMBER>/comments" --paginate

# Get all review threads to check resolution status
gh api graphql -f query='
  query($owner: String!, $repo: String!, $pr: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $pr) {
        reviewThreads(first: 100) {
          nodes {
            id
            isResolved
            path
            line
            comments(first: 20) {
              nodes {
                id
                databaseId
                body
                author { login }
                createdAt
              }
            }
          }
        }
      }
    }
  }
' -f owner=mhenrixon -f repo=kamal-proxy -F pr=<PR_NUMBER>
```

For each unresolved thread, extract:
- Thread ID (for resolving)
- Comment body (the review feedback)
- File path and line number (if inline)
- Author (to understand context)

Filter to only **unresolved** threads. Skip bot comments (CodeRabbit, dependabot), resolved threads, and PR description comments.

If there are no unresolved review comments, report that and stop.

---

## Phase 2: Read and Categorise Each Comment

For each unresolved comment, read the full body and categorise it:

| Category | Action |
|----------|--------|
| Valid fix needed | Implement the fix |
| Valid test gap | Add the missing test (table-driven, per `.claude/rules/testing.md`) |
| Valid style/consistency issue | Fix it |
| Incorrect suggestion | Push back with technical reasoning |
| Suggestion conflicts with architecture | Push back, reference `CLAUDE.md` layers (`cmd/kamal-proxy` -> `internal/cmd` -> RPC -> `internal/server`) |
| Renames `kamal-proxy` module/binary/RPC/socket | Reject outright -- `CLAUDE.md` Critical Rules #1, load-bearing across 9 RPC client call sites and the Dockerfile |
| Targets `main` or suggests committing there | Reject outright -- `main` is ff-only, see Branch Model |
| Over-engineering / YAGNI | Push back, explain why it's unnecessary |
| Unclear | Ask for clarification (do NOT implement) |

**Before categorising**, always:
1. Read the actual file and line being commented on
2. Check if the suggestion is technically correct for THIS codebase
3. Check if it would break existing functionality (run the relevant package's tests, not just read the diff)
4. Check if existing patterns/conventions contradict the suggestion (`internal/server/router_test.go`, `load_balancer_test.go` helpers are the house style for tests)
5. Check `CLAUDE.md` and `.claude/rules/*.md` -- project conventions override reviewer preferences, including fork-specific constraints (naming, branch model, tag grammar)

---

## Phase 3: Implement Accepted Fixes

For all comments you've decided to accept:

1. **Make the code changes** -- edit the relevant files
2. **Format and vet**:
   ```bash
   gofmt -l internal/ cmd/     # must print nothing -- CI enforces this
   go vet ./...
   ```
3. **Run affected tests**, then the full suite:
   ```bash
   go test ./internal/server/...   # or the specific package touched
   make test                       # go test ./... -- full suite, no Docker
   ```
   `make lint` (golangci-lint) is CI-only, not installed locally -- `gofmt -l` is the local stand-in, don't skip it.
4. **Commit** all fixes together with a conventional-commit message (`fix(scope): ...`, scope = package/feature area, e.g. `router`, `san-cert`, `rpc`):
   ```bash
   git commit -m "$(cat <<'EOF'
   fix(router): address PR review feedback

   - Description of fix 1
   - Description of fix 2
   EOF
   )"
   ```
5. **Push** to the remote branch:
   ```bash
   git push
   ```

---

## Phase 4: Reply to Every Comment

For **each** unresolved thread, reply:

### For accepted fixes:

Reply with what was fixed and the commit SHA:

```bash
gh api "repos/mhenrixon/kamal-proxy/pulls/<PR>/comments/<COMMENT_ID>/replies" \
  --method POST \
  -f 'body=Fixed in <SHA>. <Brief description of what changed>.'
```

### For rejected suggestions:

Reply with technical reasoning:

```bash
gh api "repos/mhenrixon/kamal-proxy/pulls/<PR>/comments/<COMMENT_ID>/replies" \
  --method POST \
  -f 'body=<Technical explanation of why the suggestion was not implemented>'
```

### Resolving threads (via GraphQL):

After replying, resolve the thread:

```bash
gh api graphql -f query='
  mutation($threadId: ID!) {
    resolveReviewThread(input: {threadId: $threadId}) {
      thread { isResolved }
    }
  }
' -f threadId=<THREAD_NODE_ID>
```

### For general PR comments (not inline review threads):

Reply directly:

```bash
gh pr comment <PR_NUMBER> --body "<Response addressing each point>"
```

---

## Phase 5: Verify Completion

After processing all comments, verify no unresolved threads remain:

```bash
gh api graphql -f query='
  query($owner: String!, $repo: String!, $pr: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $pr) {
        reviewThreads(first: 100) {
          totalCount
          nodes { isResolved }
        }
      }
    }
  }
' -f owner=mhenrixon -f repo=kamal-proxy -F pr=<PR_NUMBER>
```

Report the final tally: how many comments were accepted/fixed, how many were pushed back on, and confirm all threads are resolved.

---

## Response Style

When replying to comments:

- **No performative agreement** -- never say "Great point!" or "You're absolutely right!"
- **No gratitude** -- never say "Thanks for catching that"
- **Be direct** -- state the fix or the reasoning, nothing more
- **Reference commits** -- always include the short SHA when a fix was made
- **Be specific** -- when pushing back, reference actual code, not abstract principles

When pushing back:

- Use technical reasoning grounded in the actual codebase
- Reference existing patterns if the suggestion contradicts them (e.g. `testRouter(t)`, `testBackend(t, ...)` helpers over hand-rolled servers)
- Reference `CLAUDE.md` / `.claude/rules/*.md` when applicable -- especially fork constraints (naming, branch model, tag grammar, release ordering)
- Explain what would break or what edge case the reviewer missed
- If the suggestion is valid in principle but wrong for this context, say so

---

## Important Notes

- Always read the actual code before evaluating a comment -- reviewers sometimes misread diffs
- If a comment reveals a genuine bug you missed, fix it without defensiveness
- If multiple comments suggest the same change, implement it once and reference the fix in all replies
- Bot reviewers (CodeRabbit, etc.) sometimes suggest changes that conflict with project or fork conventions -- verify against `CLAUDE.md` and `.claude/rules/*.md`, not just general Go idiom
- Watch for suggestions that are correct for upstream `basecamp/kamal-proxy` but wrong here (e.g. "just use one cert manager") -- the fork's SAN batching and wildcard DNS-01 features are intentional divergence, see `CLAUDE.md` Branch map
- If a new round of review comments appears after your push (from re-review), report that to the user rather than entering an infinite loop

Now begin by determining the PR number from `$ARGUMENTS` or the current branch.
