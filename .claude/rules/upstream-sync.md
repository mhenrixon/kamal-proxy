# Upstream Sync Rules

Branch roles: `main` tracks basecamp/kamal-proxy (fast-forward only, never commit) purely so their fixes can be merged forward — we own dash-proxy, and nothing here defers to their conventions. `dash` is the integration + release branch. Feature branches merge `main` forward — never rebase published branches. `git rerere` is enabled, so previously-seen conflicts auto-replay their resolutions.

## Routine sync

```bash
git fetch upstream --tags --prune
git checkout main && git merge --ff-only upstream/main && git push origin main

# per feature branch:
git checkout san-certificate-batching && git merge main
go mod tidy && make test && git push origin san-certificate-batching

git checkout wildcard-certs && git merge main
go mod tidy && make test && git push origin wildcard-certs

# then integrate:
git checkout dash && git merge main
git merge san-certificate-batching && make test
git merge wildcard-certs && make test
gofmt -l internal/ cmd/          # must be empty; CI enforces
git push origin dash
```

## Conflict playbook

| File | Resolution |
|---|---|
| `go.mod` / `go.sum` | take main's toolchain + dep versions, keep `go-acme/lego/v4`, then `go mod tidy` |
| `internal/cmd/run.go` | union of flags — but register `--acme-email`/`--acme-directory` ONCE (pflag panics on duplicates); both cert init blocks run (SAN manager, then certificate registry) |
| `internal/server/config.go` | union: shared `ACMEEmail`/`ACMEDirectory` + wildcard's provider fields; keep both `ACMEStatePath` and `CertificateStatePath` |
| `internal/server/router.go` | union: `sanCertManager` AND `certRegistry` fields + both method pairs |
| `internal/server/service.go` | preserve upstream changes AND feature wiring; read both sides before resolving |
| `Dockerfile`, `Makefile`, `script/release` | take basecamp's unless there is a reason not to — fewer conflicts next sync. `script/release-dash` is ours |

## Release procedure

```bash
git checkout dash
script/release-dash v1.0.0.0     # validates vX.Y.Z.N grammar, make test, tags, pushes the tag
# CI publishes ghcr.io/mhenrixon/kamal-proxy:v1.0.0.0 (+ :latest)
docker buildx imagetools inspect ghcr.io/mhenrixon/kamal-proxy:v1.0.0.0   # verify amd64+arm64
```

Pick the next number yourself — it reflects what shipped here, not what basecamp happened to tag. Then update `MINIMUM_VERSION` in the `dash` gem and release it (see that repo's `.claude/rules/upstream-sync.md`); the proxy image must be published first, because `MINIMUM_VERSION` has to name a tag that exists.

## Never

- rebase published branches
- suffix tags like `v1.0.0-rc1` — `Gem::Version` sorts them below the release they name
- `git push --tags` — single-tag pushes only
- publish an image without the `org.opencontainers.image.title=kamal-proxy` label
- let the ghcr package go private — kamal pulls it anonymously
