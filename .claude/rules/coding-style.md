# Coding Style Rules

## File Organization

**MANY SMALL FILES > FEW LARGE FILES**

- High cohesion, low coupling
- 200-400 lines typical
- 800 lines maximum per file (`san_cert_manager.go` at 688 and `router_test.go` at 790 are already near the ceiling — split before adding, don't grow them)
- Extract complex logic to a dedicated file in the same package (see `cert_registry.go` vs `cert_renewal.go` vs `registry_cert_manager.go` — one concern each)
- Organize by concern: `internal/server` (router, service, load balancer, cert managers), `internal/cmd` (one file per cobra subcommand), `internal/server/acme` (provider/solver, isolated from the rest of the server package)

## Go Style

### Functions & Methods

```go
// Good: small, single-purpose, early return
func (p *PauseController) Resume() error {
	p.setState(PauseStateRunning, "")
	return nil
}

// Bad: one function doing deploy + health-check + rollout + cert issuance
func (s *Service) DoEverything(args DeployArgs) error {
	// 200 lines...
}
```

- No naked returns — name result parameters only for documentation in godoc, never to rely on bare `return`
- Table-driven tests for anything with >2 input variations:

```go
tests := []struct {
	input    string
	expected string
}{
	{"san:example.com", "san_example.com"},
	{"simple", "simple"},
	{"with/slash", "with_slash"},
}
```

(pattern from `internal/server/san_cert_manager_test.go` — keep new cert/router tests in this shape, one `t.Run` per case when the cases need independent setup)

### Error Handling

```go
// Good: wrap with %w, add context, let the caller decide what to do
func (r *CertRegistry) createSolver(cfg ProviderConfig) error {
	solver, err := newSolver(cfg)
	if err != nil {
		return fmt.Errorf("failed to create certificate solver: %w", err)
	}
	r.solver = solver
	return nil
}

// Bad: swallowing or discarding the underlying error
func (r *CertRegistry) createSolver(cfg ProviderConfig) error {
	solver, err := newSolver(cfg)
	if err != nil {
		return errors.New("solver setup failed")
	}
	r.solver = solver
	return nil
}
```

- Wrap with `fmt.Errorf("...: %w", err)` — never `errors.New` when an underlying error exists, it discards the chain `errors.Is`/`errors.As` need
- Sentinel errors live in `internal/server/errors.go` (`ErrorTargetFailedToBecomeHealthy`, `ErrorHealthCheckUnexpectedStatus`) — compare against these with `errors.Is`, don't string-match, except where the stdlib forces it (`isChunkedEncodingError` in `internal/server/errors.go` string-matches because `net/http`'s chunked-decoder errors are unexported `errors.New` values — that's a documented exception, not a pattern to copy elsewhere)
- RPC command handlers (`internal/server/commands.go`) return plain `error` across the wire — `net/rpc` gob-encodes the error string only, so wrap with enough context on the server side that the CLI's error message is still useful standalone

### Thread Safety

```go
// Good: RWMutex guarding shared controller state
func (p *PauseController) GetState() PauseState {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.State
}

func (p *PauseController) setState(newState PauseState, message string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.StopMessage = message
	p.State = newState
}

// Bad: reading/writing shared fields with no lock
func (p *PauseController) GetState() PauseState {
	return p.State // race with setState
}
```

- Every mutable field reachable from more than one goroutine (router's target map, load balancer's target list, pause controller's state) gets a `sync.Mutex`/`sync.RWMutex` and unexported field access only through locked methods
- Run `go test -race ./...` locally before pushing anything that touches `Router`, `LoadBalancer`, or `PauseController` — CI's plain `make test` does not pass `-race`, so this is on you

### Naming & Package Boundaries

- The module, binary, RPC service name, and unix socket are **`kamal-proxy`** — never rename in code, `go.mod`, `Dockerfile`, or CI. It's dialed from 9 client call sites in `internal/cmd` and execed by the `dash` gem; see `CLAUDE.md` Critical Rules and `.claude/rules/upstream-sync.md`
- New RPC verbs: define `<Verb>Args` in `internal/server/commands.go`, register the handler, add a matching `internal/cmd/<verb>.go` cobra command — follow `deploy.go`/`DeployArgs` as the template, not ad hoc structs elsewhere
- Fork-only additions (SAN batching, wildcard DNS-01) stay in their own files/packages (`san_cert_manager.go`, `internal/server/acme/`) rather than being folded into upstream files like `cert.go` — keeps merge conflicts localized per `.claude/rules/upstream-sync.md`'s conflict playbook

## gofmt & Lint

- `gofmt -l internal/ cmd/` must print nothing before you push — CI enforces this on `main` and `dash`
- `make lint` runs `golangci-lint`, not installed locally — you cannot run it here; rely on `gofmt`, `go vet` (bundled in `make test` via the standard toolchain), and careful review; CI is the real lint gate
- No `golangci-lint:disable` comments to silence a real finding — fix the code, or ask upstream/CI to justify the exception in the PR description

## Code Quality Checklist

Before marking work complete:
- [ ] Code is readable and well-named
- [ ] Functions are small and single-purpose
- [ ] Files are focused (<800 lines; split before growing a file already near the limit)
- [ ] No naked returns
- [ ] Errors wrapped with `%w` and enough context to stand alone over RPC
- [ ] Shared state behind a mutex; `go test -race ./...` run if `Router`/`LoadBalancer`/`PauseController` touched
- [ ] `gofmt -l internal/ cmd/` clean
- [ ] `make build && make test` pass
- [ ] `kamal-proxy` module/binary/RPC/socket name untouched
