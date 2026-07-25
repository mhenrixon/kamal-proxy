# Git Workflow Rules

## Commit Messages

Use conventional commits:
- `feat:` - New feature
- `fix:` - Bug fix
- `refactor:` - Code refactoring
- `perf:` - Performance improvement
- `docs:` - Documentation only
- `test:` - Adding/updating tests
- `chore:` - Maintenance tasks
- `ci:` - CI/CD changes

Format:
```
feat(scope): brief description

Longer explanation if needed. Focus on WHY, not WHAT.

Refs #123
```

Scope = the package or feature area, e.g. `san-cert`, `wildcard-certs`, `router`, `rpc`.

## Branch Model

This is a fork, not a normal repo — branch roles are fixed. Full sync mechanics live in `.claude/rules/upstream-sync.md`; this section covers where *your* commits go.

| Branch | Role | Can you commit here? |
|---|---|---|
| `main` | Fast-forward-only mirror of `basecamp/kamal-proxy` | **NEVER** |
| `dash` | Long-lived integration + release branch | Only via merge from feature branches |
| `san-certificate-batching` | SAN cert batching feature branch | Yes |
| `wildcard-certs` | DNS-01 wildcard certs feature branch | Yes |
| `feature/*`, `fix/*` | New work | Yes — root off `main` |

**Root new feature branches off `main`, not `dash`** — this keeps them upstream-PR-able (basecamp can merge them without inheriting fork-only cert code). They merge *forward* into `dash`, never the reverse, and published branches are never rebased.

## Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Refactoring
- `ci/description` - CI changes
- `chore/description` - Maintenance

## PR Workflow

1. Create branch from `main` (not `dash`)
2. Make focused, atomic commits
3. Run all validators before pushing (see checklist below)
4. Open the PR against **`dash`**, with description and test plan — `main` never receives PRs, it only fast-forwards from upstream
5. Request review
6. Squash merge when approved

## Pre-Commit Checklist

Run before EVERY commit:
```bash
gofmt -l internal/ cmd/     # Formatting — CI enforces, must print nothing
make test                   # go test ./...
```

`make lint` (golangci-lint) is CI-only — it's not installed locally. Don't skip `gofmt -l` to compensate; that's the one local check standing in for it.

## Tags & Releases

Fork tags are **four-segment**, `v<upstream-base>.<counter>` (e.g. `v0.9.2.1`) — never plain `vX.Y.Z` (that namespace belongs to upstream) and never suffix forms like `v0.9.2-dash.1` (they parse as prereleases *older* than the base and fail the gem's version check).

```bash
git checkout dash
script/release-dash v0.9.2.1     # validates tag grammar, runs make test, tags, pushes
```

- **NEVER** `git push --tags` — single-tag pushes only, `git push origin tag v0.9.2.1`
- **NEVER** hand-craft the tag — let `script/release-dash` validate the grammar and run the tests first
- Release the proxy image **before** the gem — the `dash` gem's `MINIMUM_VERSION` must name an already-published `ghcr.io/mhenrixon/kamal-proxy` tag. See `../kamal/CLAUDE.md` for gem-side ordering.

Sync mechanics (fetching upstream, merging into feature branches, the conflict playbook) live entirely in `.claude/rules/upstream-sync.md` — don't duplicate them here.

## Rules

- **NEVER** commit directly to `main`
- **NEVER** force push to shared branches (`main`, `dash`, feature branches once pushed)
- **NEVER** rebase a published branch — merge forward instead
- **NEVER** rename the module/binary/RPC service/socket away from `kamal-proxy` — see `CLAUDE.md` Critical Rules
- **ALWAYS** run `gofmt -l` + `make test` before committing
- **ALWAYS** write meaningful commit messages, WHY over WHAT
- Keep commits small and focused, one logical change per commit
