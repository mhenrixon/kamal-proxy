# Performance Rules

dash-proxy sits on every request the proxy handles — routing, forwarding, and
the TLS handshake. These rules make performance a standing part of any change
that touches those paths. There is no `docs/performance.md` yet and no
committed baseline numbers; `make bench` is the harness, this file is the
honesty directive around it.

## The prime directive

**Measure before you change. Measure after. Report both, honestly.**

A performance claim without a same-machine before/after is not allowed in a PR
or a commit message. If you didn't baseline, you don't have a delta — say
"measured after only," or `git stash`/checkout `dash` and capture the baseline
first.

## When performance is in scope

Any change to a **hot path** must come with a `make bench` before/after:

| Hot path | File | Entry point |
|---|---|---|
| Request routing | `internal/server/router.go` | `Router.ServeHTTP`, `serviceForRequest` |
| Proxy forwarding | `internal/server/target.go` | `Target.ServeHTTP`, `NewTarget`/`NewReadOnlyTarget` |
| Target selection | `internal/server/load_balancer.go` | `LoadBalancer`, `NewTargetList` |
| TLS cert lookup | `internal/server/cert_registry.go` | `CertificateRegistry.GetCertificate` (called from `tls.Config.GetCertificate` on every handshake) |
| SAN cert lookup | `internal/server/san_cert_manager.go` | equivalent `GetCertificate` path for the batching manager |

A pure docs/test/refactor change with no hot-path edit does not need a bench.
There are no `*_bench.rb`-style files here yet — if you touch a hot path with
no existing `Benchmark*` function nearby, add one in the same package
(`func BenchmarkXxx(b *testing.B)`), not a separate rig.

## Always Do

1. **Baseline first** — checkout `dash` (or stash your diff), run
   `make bench`, save the output.
2. **Bench the same way after** — apply your change, `make bench` again,
   diff the two outputs (`benchstat` if installed, otherwise eyeball
   ns/op and B/op).
3. **Report ns/op AND allocs/op** — `go test -bench=. -benchmem` gives both.
   Flag any allocs/op increase on a path that runs per-request.
4. **Distinguish proxy-level from network-level wins** — a faster
   `serviceForRequest` lookup does NOT mean faster end-to-end latency if the
   backend round-trip dominates. Say which layer moved.
5. **Note the delta in the PR body** — this repo has no CHANGELOG entry
   convention for perf; the before/after numbers belong in the PR description
   next to the diff.

## Never Do

1. **Never claim a speedup without a measured before/after.** No "this should
   be faster." Prove it with `make bench` or don't say it.
2. **Never optimize a cold path** the bench doesn't show as hot — deploy/RPC
   command handling in `internal/cmd` runs once per CLI invocation, not per
   request; three clear lines beat a clever rewrite there.
3. **Never trade routing/cert correctness for speed** — host/path matching in
   `router.go`, target health checks in `load_balancer.go`, and cert
   validation in `cert_registry.go`/`san_cert_manager.go` are not negotiable.
   A faster wrong certificate is a security bug, not a win.
4. **Never add a hard CI perf gate on a flaky threshold** — `make bench` is
   not wired into `ci.yml`; it stays a manual/local check until real
   production numbers justify a gate.
5. **Never guess at concurrency behavior** — `LoadBalancer` and
   `CertificateRegistry` are accessed from concurrent request goroutines; run
   `go test -race ./...` alongside any hot-path change, not just `make bench`.

## Gem side (../kamal)

The `dash` gem is a Ruby CLI that shells out to `ssh`/`docker` per deploy
command — it is not on a request hot path and has no bench suite. The only
rule that carries over: don't add unnecessary shelling, string building, or
SSHKit round-trips to command construction in `lib/kamal/`. If you think a
gem-side change needs a real benchmark, say so explicitly rather than
asserting it's faster — the honesty directive in this file applies whether or
not a harness exists.

## Performance Checklist (before marking perf work complete)

- [ ] Baseline captured BEFORE the change, same machine, `make bench`
- [ ] After numbers captured; before/after in the PR body
- [ ] A `BenchmarkXxx` exists for every hot path touched
- [ ] ns/op + allocs/op reported for both runs
- [ ] Proxy-level vs network-level framing is honest
- [ ] `make test` still green
- [ ] `go test -race ./...` clean for concurrent structures touched
- [ ] `gofmt -l internal/ cmd/` clean
- [ ] No routing/cert/health-check correctness traded for speed
