---
description: "Use when implementing any feature or fixing any bug -- enforces RED-GREEN-REFACTOR: write failing test first, implement minimum code to pass, then refactor."
model: sonnet
argument-hint: "[package or file, e.g. internal/server/cert_registry]"
allowed-tools: Read, Edit, Write, Bash(go test:*), Bash(make test:*), Bash(make build:*), Bash(gofmt:*)
---

# TDD Command

Enforce test-driven development with RED -> GREEN -> REFACTOR. Applies to both halves of this fork pair: Go in this repo (kamal-proxy), Ruby in `../kamal` (the `dash` gem).

## The TDD Cycle

```text
RED -> GREEN -> REFACTOR -> REPEAT

RED:      Write a failing test (test MUST fail first)
GREEN:    Write MINIMAL code to pass (nothing more)
REFACTOR: Improve code while keeping tests green
REPEAT:   Next scenario
```

## When to Use

- Implementing new features (SAN cert batching, wildcard DNS-01, RPC commands)
- Fixing bugs (write the test that reproduces the bug FIRST)
- Refactoring `internal/server` (router, load balancer, cert managers) or `internal/cmd`
- Changing RPC call sites — every `internal/cmd` command dials `kamal-proxy.sock`; a broken contract fails silently at runtime, not compile time
- Touching the gem side (`../kamal`): CLI commands, `Kamal::` classes

## Workflow

### Step 1: Write Failing Tests (RED)

Go — table-driven test with `testify`, colocated as `<file>_test.go` in the same package:

```go
// internal/server/cert_registry_test.go
package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateRegistry_RegisterDomain_NotReady(t *testing.T) {
	tmpDir := t.TempDir()
	config := CertificateRegistryConfig{
		Email:     "test@example.com",
		CachePath: filepath.Join(tmpDir, "certs"),
		StatePath: filepath.Join(tmpDir, "certificates.state"),
	}

	registry, err := NewCertificateRegistry(config)
	require.NoError(t, err)

	err = registry.RegisterDomain("app.example.com", "service1")
	assert.ErrorIs(t, err, ErrRegistryNotReady)
}
```

Ruby (gem, `../kamal`) — Minitest, mirrors upstream kamal's own suite layout:

```ruby
# test/commands/dash_test.rb
class CommandsDashTest < ActiveSupport::TestCase
  test "release image before gem enforces minimum version" do
    command = Kamal::Commands::Dash.new(config)

    assert_equal "ghcr.io/mhenrixon/kamal-proxy:v0.9.2.1", command.minimum_version_image
  end
end
```

### Step 2: Run Tests — Verify FAIL

```bash
# Go — this repo
go test ./internal/server/... -run TestCertificateRegistry_RegisterDomain_NotReady -v

# Ruby — ../kamal
cd ../kamal && bin/test test/commands/dash_test.rb
```

```text
FAIL - undefined: ErrRegistryNotReady / NoMethodError
```

**Tests MUST fail before implementing.** This confirms:
- Tests are actually running (not silently skipped)
- Tests are testing the right thing
- Implementation doesn't already exist

### Step 3: Implement Minimal Code (GREEN)

Write the minimum code to make the test pass. No speculative branches, no unrequested flags.

### Step 4: Run Tests — Verify PASS

```bash
go test ./internal/server/... -run TestCertificateRegistry_RegisterDomain_NotReady -v
# PASS
```

### Step 5: Refactor (IMPROVE)

Keep tests green while you:
- Extract functions to cut complexity
- Improve naming
- Remove duplication
- Check concurrency safety — `internal/server` is accessed from RPC handlers and health-check goroutines concurrently; guard shared state (see `sync.Mutex` usage in `load_balancer.go`, `cert_registry.go`)

### Step 6: Run Full Suite + Format Gate

```bash
make test              # go test ./...
gofmt -l internal/ cmd/  # must print nothing — CI enforces this, it's not auto-fixed
```

`make lint` (golangci-lint) is CI-only, not installed locally — `gofmt -l` is the local stand-in. Don't skip it.

## Coverage Requirements

No coverage tool is wired into CI (`ci.yml` runs build + test + golangci-lint + actionlint/zizmor, no codecov). Treat these as review bar, not a gate:

| Code Type | Minimum Coverage |
|-----------|------------------|
| All code | 80% |
| `internal/server/cert_registry.go`, `san_cert_manager.go` (cert issuance) | 100% |
| `internal/server/router.go`, `load_balancer.go` | 100% |
| `internal/cmd/*` (RPC client commands) | 100% |
| Gem `lib/kamal/commands/dash.rb` (proxy image gating) | 100% |

## Test Types to Include

### Unit Tests (config structs, cookie scope, buffer, health check)
- Happy path
- Edge cases (empty target pool, expired cert, zero-length body)
- Error conditions (`require.Error` / `assert.ErrorIs`)

### Integration Tests (router, service, RPC round-trip)
- `internal/cmd` command -> unix socket -> `internal/server` RPC handler -> response
- Deploy/rollout lifecycle (`rollout_controller_test.go` pattern: drain, swap, health-gate)
- SAN batching / wildcard DNS-01 issuance against a staging ACME directory (`acme.DefaultStagingDirectory`), never production Let's Encrypt

### Cross-repo Tests (gem side, when changing the RPC contract)
- Gem's integration tests exec the real `kamal-proxy` binary — a proxy-side RPC signature change breaks them at the boundary, not at compile time. Build `bin/kamal-proxy` locally and point `../kamal`'s test config at it before changing shared commands.

## Best Practices

**DO:**
- Write the test FIRST, before any implementation
- Run tests and verify they FAIL before implementing
- Write MINIMAL code to make tests pass
- Refactor only after tests are green
- Use `httptest.NewServer` / `t.TempDir()` to avoid real network and filesystem state (see `health_check_test.go`, `cert_registry_test.go`)
- Test against `acme.DefaultStagingDirectory`, never real Let's Encrypt, in cert tests
- Table-drive scenarios with `t.Run(name, func(t *testing.T) {...})` subtests

**DON'T:**
- Write implementation before tests
- Skip running tests after each change
- Write too much code at once
- Ignore failing tests
- Test implementation details — test behavior (RPC response, HTTP status, routing decision)
- Skip testing error paths (`RegisterDomain` when registry isn't ready, RPC dial failure, cert renewal failure)
- Touch `Dockerfile`, `Makefile`, or `script/release*` to make a test pass — those stay upstream's, per `.claude/rules/upstream-sync.md`

## Checklist

- [ ] Tests written BEFORE implementation
- [ ] Tests fail initially (RED phase verified)
- [ ] Minimal code written to pass (GREEN)
- [ ] Code refactored with tests still passing
- [ ] `gofmt -l internal/ cmd/` clean
- [ ] `make test` passes full suite
- [ ] Edge cases and error paths covered
- [ ] RPC contract changes verified against `../kamal` integration tests if `internal/cmd` or `internal/server/commands.go` touched
- [ ] `kamal-proxy` binary/RPC/socket naming untouched (see `CLAUDE.md` Critical Rules)
