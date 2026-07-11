# Testing Rules

## TDD Workflow

Follow RED -> GREEN -> REFACTOR:

1. **RED**: Write a failing test first
2. **GREEN**: Write minimal code to pass
3. **REFACTOR**: Improve code while keeping tests green

## Coverage Requirements

- **80% minimum** for all code
- **100% required** for:
  - Router (`internal/server/router.go`) — service dispatch, host matching
  - LoadBalancer (`internal/server/load_balancer.go`) — target selection, reader/writer affinity
  - SANCertManager (`internal/server/san_cert_manager.go`) — fork-only, no upstream safety net
  - Wildcard cert registry (`internal/server/cert_registry.go`, `internal/server/acme/`) — fork-only, DNS-01 provider dispatch
  - RPC commands (`internal/server/commands.go`) — the `kamal-proxy` RPC name is load-bearing; a broken command breaks every client call site

## Test Type Preference

| Component | Use |
|---|---|
| Router / Service / LoadBalancer | Unit test, `httptest.Server` backends, no Docker |
| Middleware (buffer, logging, request-id, error-page) | Unit test with `httptest.NewRecorder` |
| SANCertManager / cert registry / ACME providers | Unit test against `LetsEncryptStaging` config, no live ACME calls — mock the challenge exchange |
| `internal/cmd` (cobra commands, RPC client) | Unit test the flag/arg validation (`preRun`) directly; don't spin up a real RPC server |
| Full deploy/pause/remove flow via CLI + socket | Integration — not present in this repo today; if added, gate behind a build tag so `make test` stays Docker-free |

**Default to unit.** Nothing in `make test` requires Docker, a network call, or a real ACME directory. If a test needs any of those, it doesn't belong in the normal suite — see Integration below.

## Go Test Conventions

Table-driven tests are the house style for anything with more than two cases:

```go
func TestDeployCommand_CanonicalHostValidation(t *testing.T) {
	tests := []struct {
		name          string
		hosts         []string
		canonicalHost string
		expectError   bool
		expectedError string
	}{
		{
			name:          "valid canonical host in hosts list",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "example.com",
			expectError:   false,
		},
		// ...
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ...
		})
	}
}
```

Use `testify/assert` for non-fatal checks, `testify/require` to stop the test on setup failure (`require.NoError` before you dereference the result):

```go
router := testRouter(t)
_, target := testBackend(t, "first", http.StatusOK)

require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
	defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

statusCode, body := sendGETRequest(router, "http://example.com/")
assert.Equal(t, http.StatusOK, statusCode)
assert.Equal(t, "first", body)
```

Reuse the package's existing test helpers instead of hand-rolling servers — `testRouter(t)` (`internal/server/router_test.go`), `testBackend(t, body, status)`, `testLoadBalancerWithHandlers(t, handlers...)` (`internal/server/load_balancer_test.go`). `t.TempDir()` + `t.Cleanup(...)` for anything that touches disk or spawns a goroutine (cert managers, load balancers) — never a manual `defer os.RemoveAll`.

## No External Deps in Unit Tests

- No real ACME/Let's Encrypt calls — `SANCertManagerConfig.Directory` defaults to `LetsEncryptProduction`; tests must pass `LetsEncryptStaging` or a local mock directory, never hit the real endpoint
- No real DNS-01 provider calls (Cloudflare, Route53, ...) — `internal/server/acme/providers` tests exercise the factory/config wiring, not live provider APIs
- No Docker, no real RPC socket, no filesystem outside `t.TempDir()`
- `httptest.NewServer` / `httptest.NewRecorder` stand in for real backends and clients everywhere

## Test Checklist

- [ ] Tests written BEFORE implementation
- [ ] `make test` passes (`go test ./...`)
- [ ] `gofmt -l internal/ cmd/` empty — CI enforces, `golangci-lint` isn't installed locally so gofmt is your only local signal until CI runs
- [ ] Coverage meets requirements (100% for Router, LoadBalancer, SANCertManager, cert registry, RPC commands)
- [ ] No skipped tests without a reason
- [ ] Edge cases covered (empty target list, illegal host patterns, unhealthy targets, expired/missing certs)
- [ ] Error paths tested (ACME failures, RPC dial failures, invalid TLS host config)
- [ ] New fork-only code (SAN batching, wildcard certs) has its own tests — it has no upstream test suite backing it up; see `CLAUDE.md` Never-Do #1 on why `kamal-proxy` naming can't drift

## Commands

```bash
make test    # go test ./... — full suite, no Docker
make bench   # go test -bench=. -benchmem -run=^# ./...
make lint    # golangci-lint run — NOT installed locally; CI is authoritative
make docker && docker run --rm kamal-proxy kamal-proxy -h   # image smoke test
```

## Cross-References

- `CLAUDE.md` — architecture layers, branch map, release ordering
- `.claude/rules/upstream-sync.md` — merge conflict playbook for `router.go`/`config.go`/`service.go` during sync; test after every merge, not just before push
- `ROADMAP.md` — planned fork features that will need their own test coverage before merging to `dash`
