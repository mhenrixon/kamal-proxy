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

Branch roles are fixed. `main` still tracks basecamp so their fixes can be merged forward, but nothing here is shaped for their benefit. Full sync mechanics live in `.claude/rules/upstream-sync.md`; this section covers where *your* commits go.

| Branch | Role | Can you commit here? |
|---|---|---|
| `dash` | **This fork's main branch** — every feature lands here | Only via merge from feature branches |
| `main` | Fast-forward-only mirror of `basecamp/kamal-proxy` | **NEVER** |
| `san-certificate-batching` | SAN cert batching feature branch | Yes |
| `wildcard-certs` | DNS-01 wildcard certs feature branch | Yes |
| `feature/*`, `fix/*` | New work | Yes — root off `dash` |

**Root new feature branches off `dash`.** `dash` is this fork's main branch, and upstream
mergeability is not a constraint on our design — we build what is best for `dash` and diverge
from basecamp where that is better. (Same call as the `../kamal` fork.) Rooting off `main`
instead produces PRs that run no CI and conflict on every fork-only file, which is why we
stopped doing it.

`main` still exists so upstream fixes can be merged *forward* into `dash`. It is a source,
never a target. Published branches are never rebased.

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
git checkout dash
script/release-dash v1.0.0.0     # validates tag grammar, runs make test, tags, pushes
```

- **NEVER** `git push --tags` — single-tag pushes only, `git push origin tag v1.0.0.0`
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
