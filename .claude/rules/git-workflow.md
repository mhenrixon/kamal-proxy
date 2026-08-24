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

Since the 2026-08 clean break (zoolutions/dash#115) there is no upstream and no mirror branch.

| Branch | Role | Can you commit here? |
|---|---|---|
| `main` | **The** branch — default, protected by ruleset, releases cut from here | Only via PR merge |
| `feature/*`, `fix/*` | New work | Yes — root off `main` |

Root new feature branches off `main`, open the PR against `main`. Published branches are
never rebased. The old `dash` branch was fast-forwarded into `main` and deleted; the dormant
cert feature branches (`san-certificate-batching`, `wildcard-certs`) are merged history.

## Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Refactoring
- `ci/description` - CI changes
- `chore/description` - Maintenance

## PR Workflow

1. Create branch from `main`
2. Make focused, atomic commits
3. Run all validators before pushing (see checklist below)
4. Open the PR against **`main`**, with description and test plan
5. Request review
6. Squash merge when approved (the ruleset requires linear history)

## Pre-Commit Checklist

Run before EVERY commit:
```bash
gofmt -l internal/ cmd/     # Formatting — CI enforces, must print nothing
make test                   # go test ./...
```

`make lint` runs golangci-lint. Install the version `.github/workflows/ci.yml` pins so a local run means what CI means:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3
```

`gofmt` does not catch what staticcheck does, so run `make lint` before pushing rather than finding out from CI.

## Tags & Releases

Release tags are **four-segment**, `vX.Y.Z.N` (e.g. `v1.0.0.0`).

The shape is unchanged from when this was a fork; the meaning is not. The first three segments used to be whatever basecamp had tagged, with `N` counting fork-only releases on top. We own dash-proxy now, so all four are ours to choose and the number reflects what shipped here. `script/release-dash` also accepts plain `vX.Y.Z`, so nobody is blocked by the distinction.

Never use suffix forms like `v1.0.0-rc1`: the gem compares the image tag with `Gem::Version`, which reads a hyphen suffix as a prerelease sorting *below* the release it names — a tag that sorts below itself fails the `MINIMUM_VERSION` check.

```bash
git checkout main
script/release-dash v1.0.0.0     # validates tag grammar, runs make test, tags, pushes
```

- **NEVER** `git push --tags` — single-tag pushes only, `git push origin tag v1.0.0.0`
- **NEVER** hand-craft the tag — let `script/release-dash` validate the grammar and run the tests first
- Release the proxy image **before** the gem — the `dash` gem's `MINIMUM_VERSION` must name an already-published `ghcr.io/zoolutions/dash-proxy` tag. See `../kamal/CLAUDE.md` for gem-side ordering.

There is no upstream sync anymore — `.claude/rules/upstream-sync.md` is a historical note.

## Rules

- **NEVER** push directly to `main` — everything lands via PR (ruleset-enforced; admin bypass is for migrations, not routine)
- **NEVER** force push to shared branches (`main`, feature branches once pushed)
- **NEVER** rebase a published branch — merge forward instead
- **NEVER** rename the module/binary/RPC service/socket away from `kamal-proxy` — see `CLAUDE.md` Critical Rules
- **ALWAYS** run `gofmt -l` + `make test` before committing
- **ALWAYS** write meaningful commit messages, WHY over WHAT
- Keep commits small and focused, one logical change per commit
