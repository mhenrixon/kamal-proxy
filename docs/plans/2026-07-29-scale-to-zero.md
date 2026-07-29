# Scale-to-zero idle services (issue #19) — implementation plan

Produced 2026-07-29 by a scout/design/judge workflow against dash @ cad460e. Ports basecamp/kamal-proxy#228 (which supersedes the closed #197 issue #19 names).

# Scale-to-zero on `dash` — decided implementation plan

**Provenance note (read first):** the working tree is on `feature/observability-batch`, not `feature/scale-to-zero`, and is dirty (`log_format.go`, `trace_context.go`, `implementation-notes.md` untracked; `logging_middleware.go` modified). HEAD is `cad460e`. Branch off a clean `dash` before starting. Line numbers below are from HEAD as read.

Every divergence from both input plans is anchored to a line I opened.

---

## Decision summary

| # | Question | Decision |
|---|---|---|
| 1 | IdleController vs PauseController | **Separate controller.** PauseController is the wrong shape; its broadcast idiom is copied. |
| 2 | Wake-hold position | `serviceRequestWithTarget`, immediately after `handlePausedAndStoppedRequests` (service.go:768). |
| 3 | Container identity | Derive from `targetURL.Hostname()`; **`--sleep-container` overrides**; deploy-time preflight proves it. Derivation is *not* reliable — see §3. |
| 4 | What blocks sleep | One signal: `IdleController.inflight`, released by a `defer` that cannot run until the stream closes. |
| 5 | Health checks vs stopped container | Single-target checks are **already stopped**, so nothing is marked unhealthy *and the wake has no readiness signal*. Fixed by `SuspendForSleep`/`ResumeFromSleep` + a locked `waitForHealthyContext` read. |
| 6 | Flags | `deploy --sleep-after` / `--wake-timeout` / `--sleep-container`; `run --docker-socket` (default **empty**). |
| 7 | Persistence | `ServiceOptions.{SleepAfter,WakeTimeout,SleepContainers}` + one `idle_state` string. Old files decode to `active`, feature off. |

---

## 1. Separate `IdleController`, not an extended `PauseController`

Both input plans said separate. I agree, and the reasons are verifiable rather than stylistic. `PauseController.Wait()` (pause_controller.go:108) is structurally wrong in four ways that cannot be patched without changing pause semantics for every existing user:

1. **No side effect.** `Wait()` is a pure observer — it never causes the state to change. Sleep→wake requires the *first* waiter to fire `StartContainer`. Bolting that in would fire a network call from inside `getWaitState`'s `RLock` (pause_controller.go:133-142).
2. **No context.** `Wait()` takes no `context.Context` and never selects on `r.Context().Done()`. A client that hangs up mid-wake would leave a goroutine parked for the full timeout. Adding a parameter changes every pause call site.
3. **One enum, two orthogonal axes.** Pause is admin-driven; sleep is traffic-driven. "Paused *and* sleeping" is a real state that a single `State` field cannot hold, and `Resume()` (pause_controller.go:100) would silently clobber a sleep.
4. **`time.After(p.FailAfter)` per call** inside the read lock (pause_controller.go:138) — one never-stopped timer per in-flight request.

**What I do copy:** the close-only broadcast channel (nothing is ever *sent*; `close()` is the broadcast, and waiters re-read state after waking — pause_controller.go:119-124), and the "re-drive the state machine on restore rather than trusting the serialized field" idiom from `UnmarshalJSON` (pause_controller.go:51-68).

**Consequence I am taking deliberately:** the two controllers compose by *position*, not by shared state. Because the idle gate sits below the pause gate (§2), a paused or stopped service's requests never reach `BeginRequest` at all. That is why I ship no wake-side interlock — see §10 for the one interlock I do ship, and why.

---

## 2. Where the wake-hold sits — and why not one layer up or down

**Exact position:** `internal/server/service.go`, inside `serviceRequestWithTarget`, between `handlePausedAndStoppedRequests` (line 768) and `r = s.rewriteRequest(r)` (line 773).

```go
	if s.handlePausedAndStoppedRequests(w, r) {
		return
	}

	// After every gate above, so that no blocked, throttled, unauthenticated or
	// redirected request can spend a container start -- upstream had none of
	// those gates, which is why its own placement one layer up was safe there
	// and is a denial-of-wallet vector here. Before target selection, so the
	// request body is still unread when the hold begins.
	handled, endIdleRequest := s.handleIdleRequest(w, r)
	if endIdleRequest != nil {
		defer endIdleRequest()
	}
	if handled {
		return
	}

	// Last, so that everything above -- the health check exemptions, the
	// redirects, the allow list -- still sees the path the client asked for.
	r = s.rewriteRequest(r)
```

**Why not one layer up** (`Service.ServeHTTP`, service.go:397 — where #228 put it). Everything in this list is *below* `ServeHTTP` on dash and *above* the chosen point, and each one is a concrete regression at the higher position:

| Gate | Line | What #228's placement costs |
|---|---|---|
| `WithRequestDeadlineMiddleware` | service.go:695 | Wake escapes `--request-timeout` / `--path-request-timeout`. The existing comment promises the deadline "covers pause waits and target selection". |
| `certManager.HTTPHandler` | service.go:727 | An **ACME HTTP-01 challenge starts a container**. Per-service `autocert` (TLS-on-demand) has no root-level escape. |
| `WithErrorPageMiddleware` | service.go:707 | Wake-failure 503 renders the *root* error page (server.go:388), not the service's `--error-pages`. |
| `WithCompressionMiddleware` | service.go:720 | Wake-failure body uncompressed, unlike every other 503. |
| `rejectDisallowedIP` | service.go:740 | A blocked IP spends a `docker start`. |
| `handleRedirectsIfNeeded` | service.go:749 | A 301 that never reaches the target wakes a container. |
| `rejectRateLimited` | service.go:756 | A flood spends one `docker start` per burst. |
| `rejectUnauthenticated` | service.go:764 | **An anonymous client spends money.** |

**Why not one layer down** (`startLoadBalancerRequest`, service.go:781). It holds `s.serviceLock.RLock()` for its whole body:

```go
func (s *Service) startLoadBalancerRequest(w http.ResponseWriter, r *http.Request) func() {
	s.serviceLock.RLock()
	defer s.serviceLock.RUnlock()
	...
}
```

A 3-second wake there blocks `UpdateLoadBalancer`'s write lock (service.go:359) for 3 seconds — i.e. **every deploy stalls behind every wake.**

**Why not further down still** (inside `LoadBalancer.StartRequest` or `serveWithRetries`). This is the trap: for the single-target service that scale-to-zero actually targets, `updateHealthyTargets` calls `lb.all.StopHealthChecks()` the moment the target first goes healthy (load_balancer.go:309-315, verified). The stopped container therefore stays `TargetStateHealthy`, `claimTarget` **succeeds**, and the request goes straight to a connection-refused 502 via `handleProxyError`. The selection-failure retry path (`ErrorNoHealthyTargets`) never fires. dash's retry machinery cannot be the hold.

**Body safety.** The point of no return is `target.go:249`, `t.handlerForRequest(req).ServeHTTP(tw, req)` — where either `RequestBufferMiddleware` drains the body or `ReverseProxy` streams it. Everything above reads headers and URL only; `rewriteRequest` shallow-copies and shares the same `Body` (redirect_rules.go:139). `net/http` does not read a request body until the handler asks. So a chunked POST parked for 3 seconds is handed on byte-for-byte unread. **No buffering, no `TeeReader`, no `--buffer-requests` requirement.**

---

## 3. Container identity — the honest answer

**The proxy cannot reliably derive the container reference. It can derive it in the two common topologies and not in the others.** Neither input plan addressed this fully; both guarded only IP literals.

What the proxy has is `host[:port]`, and nothing else. `hostRegex` is `^(\w[-_.\w+]+)(:\d+)?$` (target.go:27); `parseTargetSpec` strips `;weight=N` first (target_weight.go:31).

| Topology | `--target` carries | `POST /containers/{ref}/start` |
|---|---|---|
| **Kamal** | 12-char **container short ID** — `docker container ls --filter name=… --quiet` (kamal `commands/base.rb:17`), joined with the port in `configuration/proxy.rb:146` | ✅ Docker accepts an unambiguous ID prefix |
| **Compose, container name** (this repo's `example/README.md` uses `--target example-web-1`) | container name | ✅ |
| **Compose, service alias** (`--target web:3000`) | a **network alias**, not a container name | ❌ **404** |
| Custom `--network-alias` | alias | ❌ 404 |
| IP literal (`10.0.0.5:3000` — `hostRegex` accepts it) | address | ❌ 404 |
| External DNS name | hostname | ❌ 404 |

Case 3 is a *normal* way to write a Compose target, and it silently 404s. So:

**Derivation (default):**

```go
// ContainerRef returns the container this target's address names: its hostname,
// which is a container short ID in a Kamal deployment and a container name in
// the Compose example. It is a best guess -- a Compose service alias or a
// custom network alias resolves over Docker's DNS but names no container -- so
// --sleep-container exists to state the reference explicitly, and the deploy
// preflight is what turns a wrong guess into an error on the operator's
// terminal instead of a 503 an hour later.
//
// An IP literal is rejected outright: hostRegex accepts "10.0.0.5:3000", and no
// container runtime could ever act on it. Bracketed IPv6 never reaches here --
// hostRegex rejects it before a Target is built.
func (t *Target) ContainerRef() (string, bool) {
	host := t.targetURL.Hostname()
	if net.ParseIP(host) != nil {
		return "", false
	}
	return host, true
}
```

**Override (`--sleep-container`, repeatable).** When set it replaces the derived set entirely, so the "which target maps to which container" question never arises:

```go
// SleepContainers names the containers to stop and start for --sleep-after,
// replacing what the proxy would infer from the target addresses. Set it when a
// target names a network alias rather than a container -- "--target web:3000"
// under Compose resolves over Docker's DNS but is not a container name.
//
// Unlike the inferred set this does not follow a redeploy, so under Kamal --
// where the target is a per-release container id -- leave it unset and let the
// proxy infer.
SleepContainers []string `json:"sleep_containers,omitempty"`
```

```go
// containerRefsLocked names the containers behind this service's write targets
// across both slots. Read targets are replicas whose lifecycle the proxy does
// not own, so they are never stopped.
//
// Callers hold the service write lock: initialize() runs unlocked from
// UpdateOptions, so collecting refs there -- as upstream does -- races a
// concurrent redeploy mutating s.active.
func (s *Service) containerRefsLocked(options ServiceOptions) []string {
	if len(options.SleepContainers) > 0 {
		return slices.Clone(options.SleepContainers)
	}

	refs := []string{}
	for _, lb := range []*LoadBalancer{s.active, s.rollout} {
		if lb == nil {
			continue
		}
		for _, target := range lb.WriteTargets() {
			if ref, ok := target.ContainerRef(); ok {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}
```

**Preflight closes the guessing gap.** In `Router.DeployService`, after `options.Validate()`:

```go
// validateSleepConfiguration proves, in one round trip at deploy time, that the
// socket is mounted, the daemon answers, the API version negotiates, and every
// reference names a container this daemon knows. Upstream discovered all of
// that at the first idle timeout instead, marked the service asleep regardless,
// and then 503'd every request for a container that was running fine.
func (r *Router) validateSleepConfiguration(options ServiceOptions, targetURLs []string, targetOptions TargetOptions) error {
	if options.SleepAfter <= 0 {
		return nil
	}

	if r.lifecycle == nil {
		return ErrNoContainerLifecycle
	}

	refs := options.SleepContainers
	if len(refs) == 0 {
		targets, err := NewTargetList(targetURLs, nil, targetOptions)
		if err != nil {
			return err
		}

		for _, target := range targets {
			ref, ok := target.ContainerRef()
			if !ok {
				return fmt.Errorf("%w: target %s is an address, not a container; name the container with --sleep-container",
					ErrNotAContainerRef, target.Address())
			}
			refs = append(refs, ref)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), containerPreflightTimeout)
	defer cancel()

	for _, ref := range refs {
		switch err := r.lifecycle.ContainerExists(ctx, ref); {
		case err == nil:

		case errors.Is(err, ErrContainerNotFound):
			return fmt.Errorf("%w: no container named %q; if the target names a network alias rather than a container, set --sleep-container",
				ErrNotAContainerRef, ref)

		case errors.Is(err, ErrContainerInspectForbidden):
			// A hardened socket proxy commonly allows POST .../start and
			// .../stop while denying inspect. Refusing the deploy for that
			// would lock out exactly the operators doing the right thing, so
			// this is the one preflight failure that is a warning.
			slog.Warn("Cannot verify container for --sleep-after; the socket denies inspect",
				"container", ref, "error", err)

		default:
			return fmt.Errorf("cannot manage container %q for --sleep-after: %w", ref, err)
		}
	}

	return nil
}
```

---

## 4. What prevents sleeping — one signal, three cases

**The signal is `IdleController.inflight`.** There is exactly one, and it covers all three cases because of *where* its release is deferred.

- **Incremented:** `IdleController.admit()`, under `c.lock`, when the state is `Active`.
- **Decremented:** `IdleController.EndRequest()`, via the `defer endIdleRequest()` in `serviceRequestWithTarget` (§2).
- **Read:** `IdleController.trySleep()`, under `c.lock`, as `c.inflight != 0`.

| Case | Concrete mechanism |
|---|---|
| **Ordinary request** | `defer endIdleRequest()` runs when `serviceRequestWithTarget` returns — after `sendRequest()` (service.go:775-777). |
| **WebSocket** | `sendRequest()` → `Target.SendRequest` (target.go:240) → `ReverseProxy` handles the upgrade and **does not return until the hijacked connection closes**. `targetResponseWriter.Hijack` (target.go:649) flags it but does not release anything. So `endIdleRequest` cannot run for the life of the socket. |
| **SSE** | Identical: `ReverseProxy` streams `text/event-stream` with the stdlib's automatic `FlushInterval: -1` (no explicit interval set, target.go:371) and returns only on body close. |

This is the same guarantee `Target.inflight` already gives `Drain` (target.go:252), reached without touching `Target`'s map or its lock. **No special-casing of WebSocket or SSE anywhere in this feature.**

Deliberately *not* counted as activity — otherwise a 1 Hz uptime monitor pins a service awake forever:

```go
if isInternalRequest(r) || s.targetOptions.IsHealthCheckRequest(r) { ... }
```

matching the exemption `rejectDisallowedIP`, `rejectRateLimited` and `rejectUnauthenticated` already use. `isInternalRequest` (service.go:73) catches the proxy's own TLS-on-demand probes.

---

## 5. Health checks against a stopped container

**Answer: it depends on target count, and the single-target case — the one scale-to-zero actually targets — is worse than "marked unhealthy".**

| Shape | What happens when the container stops | Effect on wake |
|---|---|---|
| **Single target, default** | `updateHealthyTargets` called `lb.all.StopHealthChecks()` at first-healthy (load_balancer.go:309-315). **No probe runs.** Target stays `TargetStateHealthy`, stays in `lb.writers`. Requests dial a dead socket → `handleProxyError` → **502**, forever. | **Breaks wake, silently.** `markHealthy()` already fired, so `waitForHealthyContext` is already cancelled and `WaitUntilHealthy` returns `nil` **instantly** — the wake would report ready against a container that has not booted. |
| **Multi-target** | Probes run forever. First failure demotes `Healthy → Unhealthy` (target.go:330-334), target leaves the pool, `nextTarget` returns nil → **503**. Probes keep hammering a deliberately-stopped container every second. | Wake works, but noisy: `"Target health updated … unhealthy"` per interval per target for the whole sleep. |
| **Restored under `--recheck-targets-on-restore`** | `persistentHealthChecks` is pinned (load_balancer.go:180), so the single-target auto-stop never fires — behaves like multi-target. | Same noise, indefinitely. |

**The fix — two `LoadBalancer` methods and one lock correction.**

```go
// SuspendForSleep empties the pool and stops probing, so a container that is
// deliberately stopped is neither routed to nor dialled once a second. It is
// called before the containers go down: the idle controller holds arriving
// requests in Stopping while this runs, so an empty pool is never observable.
func (lb *LoadBalancer) SuspendForSleep() {
	lb.all.StopHealthChecks()

	for _, target := range lb.all {
		target.updateState(TargetStateUnhealthy)
	}

	lb.lock.Lock()
	defer lb.lock.Unlock()

	lb.writers = TargetList{}
	lb.readers = TargetList{}
}

// ResumeFromSleep puts the pool back in the state a fresh deployment starts in
// -- unverified, health-checked -- and re-arms WaitUntilHealthy so a caller can
// wait for the woken containers to actually answer.
//
// Re-arming is the whole point. A single-target pool stops probing at
// first-healthy and MarkAllHealthy assumes health on restore, so without this
// waitForHealthyContext is already cancelled and WaitUntilHealthy returns nil
// against a container that has not started.
//
// The previous context is replaced, not cancelled: WaitUntilHealthy reports any
// non-deadline cancellation as success, so cancelling would tell a concurrent
// waiter "healthy" at the exact moment every target was marked unverified.
func (lb *LoadBalancer) ResumeFromSleep() {
	lb.lock.Lock()
	lb.waitForHealthyContext, lb.markHealthy = context.WithCancel(context.Background())
	lb.lock.Unlock()

	for _, target := range lb.all {
		target.updateState(TargetStateAdding)
	}

	// RestartHealthChecks, not BeginHealthChecks: the latter assigns
	// t.stateConsumer outside the inflight lock, which is only safe before a
	// target serves anything. NewHealthCheck runs one immediate probe before it
	// starts ticking, so readiness costs a round trip, not a check interval.
	lb.all.RestartHealthChecks()
}
```

`TargetStateAdding` is the correct resume state: `HealthCheckCompleted(true)` promotes `Adding → Healthy` (target.go:317-322), and `HealthCheckCompleted(false)` only ever demotes `Healthy → Unhealthy` (target.go:330-334) — so a container that never comes up stays out of the pool rather than flapping.

Readiness then arrives through machinery that already exists: `HealthCheckCompleted(true)` → `TargetStateChanged` → `updateHealthyTargets` → `healthyCount == len(lb.all)` → `markHealthy()` → the wake's `WaitUntilHealthy` returns. And the single-target `StopHealthChecks()` fires again, so a woken service returns to zero background probing. **A woken container is held to exactly the standard a freshly deployed one is** (`createLoadBalancer`, router.go:550).

**Required companion fix** — `waitForHealthyContext` is now written at runtime, so the read at load_balancer.go:153 must take the lock or it is a data race that `-race` will catch:

```go
func (lb *LoadBalancer) WaitUntilHealthy(timeout time.Duration) error {
	lb.lock.Lock()
	parent := lb.waitForHealthyContext
	lb.lock.Unlock()

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	<-ctx.Done()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w (%s)", ErrorTargetFailedToBecomeHealthy, timeout)
	}

	return nil
}
```

And in `target.go`, splitting `BeginHealthChecks` without touching the unsynchronized `stateConsumer` write:

```go
func (t *Target) BeginHealthChecks(stateConsumer TargetStateConsumer) {
	t.stateConsumer = stateConsumer
	t.RestartHealthChecks()
}

// RestartHealthChecks re-arms checking on a target whose checks were stopped,
// leaving the state consumer alone -- unlike BeginHealthChecks, which assigns it
// outside the inflight lock and is therefore only safe before a target serves.
func (t *Target) RestartHealthChecks() {
	t.withInflightLock(func() {
		if t.healthcheck != nil {
			t.healthcheck.Close()
		}

		t.healthcheck = NewHealthCheck(
			t,
			t.buildHealthCheckURL(),
			t.options.HealthCheckConfig.Interval,
			t.options.HealthCheckConfig.Timeout,
			t.options.HealthCheckConfig.Host,
		)
	})
}
```

**`health_check.go` needs no change at all.** dash's `BeginHealthChecks` (target.go:284-301) already closes the previous healthcheck inside `withInflightLock`, which is the only thing #228's `newHealthCheck`/`Start()`/`sync.Once` split bought.

One more guard, in `Service.RecheckTargetHealth` (service.go:577), so `--recheck-targets-on-restore` does not probe a sleeping service:

```go
	if s.idleController != nil && s.idleController.State() != IdleStateActive {
		return
	}
```

---

## 6. Flags

### `kamal-proxy run`

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--docker-socket` | `KAMAL_PROXY_DOCKER_SOCKET`, `DOCKER_SOCKET` | **`""` (disabled)** | Docker socket path. Validated in `preRun` to exist and be a socket. |

```go
runCommand.cmd.Flags().StringVar(&globalConfig.DockerSocketPath, "docker-socket", getEnvString("DOCKER_SOCKET", ""),
	"Path to the Docker socket, enabling --sleep-after for deployed services (default empty, disabled). Mounting this socket into an internet-facing proxy grants it root-equivalent control of the host")
```

Empty, not `/var/run/docker.sock`. #228's flag was a no-op against its own default while the client was constructed unconditionally — "opt-in" in name only. `ROADMAP.md:49` already commits to opt-in.

`preRun` (which exists since `--min-tls`, run.go:68):

```go
	// Checked at boot, with the path in the message, rather than at the first
	// idle timeout an hour later.
	if globalConfig.DockerSocketPath != "" {
		info, err := os.Stat(globalConfig.DockerSocketPath)
		if err != nil {
			return fmt.Errorf("docker-socket %q is not reachable: %w", globalConfig.DockerSocketPath, err)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("docker-socket %q is not a socket", globalConfig.DockerSocketPath)
		}
	}
```

Wired with a **setter, not a constructor argument** — `NewRouter(statePath)` has 43 call sites, and `SetSANCertManager` / `SetDynamicDomainManager` / `SetCertificateRegistry` are the established idiom. Placed after `RestoreLastSavedState` so it reconciles restored services:

```go
	if globalConfig.DockerSocketPath != "" {
		router.SetContainerLifecycle(server.NewDockerClient(globalConfig.DockerSocketPath))
	}
```

### `kamal-proxy deploy`

| Flag | Default | Meaning |
|---|---|---|
| `--sleep-after` | `0` (never) | Stop this service's containers after this long without traffic. |
| `--wake-timeout` | `30s` | Max hold while they start and pass a health check. |
| `--sleep-container` | none (infer) | Container to stop/start, repeatable; replaces inference. |

```go
deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.SleepAfter, "sleep-after", 0,
	"Stop this service's target containers after this long with no traffic, and start them again on the next request (default 0, never). Requires the proxy to run with --docker-socket. Health checks and the proxy's own TLS probes are not traffic and never wake a sleeping service")
deployCommand.cmd.Flags().DurationVar(&deployCommand.args.ServiceOptions.WakeTimeout, "wake-timeout", server.DefaultWakeTimeout,
	"Maximum time a request waits for a sleeping service's containers to start and pass a health check before failing with 503")
deployCommand.cmd.Flags().StringArrayVar(&deployCommand.args.ServiceOptions.SleepContainers, "sleep-container", nil,
	"Container to stop and start for --sleep-after, replacing what the proxy infers from the target address. Needed when a target names a network alias rather than a container (may be specified multiple times)")
```

**Not `--idle-timeout`.** Verified collision: `run --idle-timeout` already exists for HTTP keep-alive (run.go:53 → `Config.IdleTimeout`, config.go:71, `DefaultIdleTimeout = 60s` at config.go:24). Two flags with one name and two unrelated meanings is an operator trap no compiler catches. `--sleep-after` also puts the flag, the persisted state name (`sleeping`), the `list` column and the log lines in one vocabulary.

The cobra default is `DefaultWakeTimeout` so `--help` is honest, **and** `Normalize()` maps `0 → DefaultWakeTimeout` so restored state files and direct RPC callers get the same value:

```go
func (so *ServiceOptions) Normalize() {
	so.Hosts = NormalizeHosts(so.Hosts)
	so.PathPrefixes = NormalizePathPrefixes(so.PathPrefixes)
	so.Compression.Normalize()

	if so.SleepAfter > 0 && so.WakeTimeout <= 0 {
		so.WakeTimeout = DefaultWakeTimeout
	}
}
```

Validation joins the existing chain in `Validate()` (service.go:228-254), in `service_idle.go`:

```go
func (so ServiceOptions) validateSleep() error {
	if so.SleepAfter < 0 || so.WakeTimeout < 0 {
		return fmt.Errorf("%w: sleep-after and wake-timeout cannot be negative", ErrServiceOptionsInvalid)
	}

	if so.SleepAfter > 0 && so.TLSOnDemandURL != "" {
		// An on-demand check asks the backend, at handshake time, whether a host
		// may have a certificate. A sleeping backend cannot answer, and waking
		// one would let any SNI on the internet start a container.
		return fmt.Errorf("%w: sleep-after cannot be used with a TLS on-demand URL", ErrServiceOptionsInvalid)
	}

	if so.SleepAfter <= 0 && len(so.SleepContainers) > 0 {
		return fmt.Errorf("%w: sleep-container requires sleep-after", ErrServiceOptionsInvalid)
	}

	return nil
}
```

### `kamal-proxy list`

Compose into the existing `State` column. `ServiceDescription` is gob-encoded and router.go:70-72 mandates append-only; a new *value* in an existing string field is not a schema change, and a CLI built before this prints it verbatim.

```go
// describeServiceState reports the one state an operator most needs to see. A
// paused or stopped service says so -- that is a human decision and it outranks
// anything traffic-driven -- and otherwise a sleeping or waking service says
// that rather than "running".
func describeServiceState(service *Service) string {
	if pause := service.pauseController.GetState(); pause != PauseStateRunning {
		return pause.String()
	}

	if service.idleController != nil {
		if idle := service.idleController.State(); idle != IdleStateActive {
			return idle.String()
		}
	}

	return PauseStateRunning.String()
}
```

Column now reads `running | paused | stopped | sleeping | waking | stopping`.

---

## 7. Persistence

**Added to the state file — two places, nothing else.**

1. **`ServiceOptions`** (persisted whole as `marshalledService.Options`, service.go:410), all `omitempty`:

```go
	SleepAfter      time.Duration `json:"sleep_after,omitempty"`
	WakeTimeout     time.Duration `json:"wake_timeout,omitempty"`
	SleepContainers []string      `json:"sleep_containers,omitempty"`
```

2. **`marshalledService`** — one string, not #228's whole `IdleController` JSON codec:

```go
	// IdleState is written as a name rather than an enum's number: the state
	// file outlives proxy versions and operators read it. Absent -- every state
	// file written before scale-to-zero existed -- parses to active, which is
	// also what SleepAfter == 0 produces, so the feature restores off.
	IdleState string `json:"idle_state,omitempty"`
```

`MarshalJSON` writes `s.idleStateName()`; `UnmarshalJSON` sets `s.restoredIdleState = parseIdleState(ms.IdleState)` and **creates no controller**. `parseIdleState` folds `stopping` and `waking` down to `sleeping` on both write and read: a proxy that died mid-transition does not know whether the container moved, and waking from `sleeping` is safe precisely because `docker start` on a running container answers `304`, which the client treats as success.

**A pre-existing state file decodes to:** no `sleep_after` → `SleepAfter == 0`; no `idle_state` → `""` → `IdleStateActive`; `configureIdleController` sees `SleepAfter <= 0` → `s.idleController` stays nil → `handleIdleRequest` returns immediately → **byte-for-byte today's behavior, and the re-marshalled file is byte-identical too** (every new key is `omitempty`).

**Downgrade** (new file, older binary): `encoding/json` drops unknown fields, so the service restores with no idle awareness while its containers may be stopped and `MarkAllHealthy()` (service.go:481) claims otherwise → 502s until someone runs `docker start`. Documented limitation, not fixable from this side.

**Why `UnmarshalJSON` must not build the controller.** It ends in `s.initialize(...)` (service.go:493) — at which point `s.lifecycle` is still nil, because the router can only inject it after decoding. #228 built the controller there and started its timer goroutine, so a persisted `Active` state with a small idle timeout could reach `StopContainer` on a **nil interface**. Here the controller is built by `SetContainerLifecycle`, which the router calls per service after restore:

```go
// SetContainerLifecycle installs the runtime that starts and stops this
// service's containers and builds the idle controller around it. Restored
// services get theirs after the state file is decoded, which is exactly why
// UnmarshalJSON never creates one.
func (s *Service) SetContainerLifecycle(lifecycle ContainerLifecycle) {
	s.lifecycle = lifecycle
	s.configureIdleController(s.options)

	if s.idleController == nil || s.idleController.State() != IdleStateSleeping {
		return
	}

	// Restore assumed every target healthy (MarkAllHealthy, service.go:481).
	// For a sleeping service that is a healthy pool pointing at a stopped
	// container -- and under --recheck-targets-on-restore, a probe against it
	// every second. Put it back the way sleeping left it.
	s.suspendForSleep()
}
```

**When state is written.** `IdleController` calls `persist` on the `Active↔Sleeping` edges only — two `saveStateSnapshot` calls per full cycle — **synchronously from the controller's own goroutine**, never `go fn()` and never from a request goroutine. Both transitions already run off the request path (`trySleep` on the timer goroutine, `finishWake` on the wake goroutine), so no detachment is needed. `saveStateSnapshot` (router.go:610) marshals to `[]byte` and writes under `saveLock` via `writeFileAtomic` — **#228's file-leak fix and `stateLock` hunk are already superseded on dash; drop them.**

**Companion fix required.** `saveStateSnapshot` marshals under `r.withReadLock`, but `Service.MarshalJSON` (service.go:425) reads `s.active` / `s.rollout` with **no `serviceLock`**. That is a pre-existing race, and persisting from a sleep/wake makes it far more reachable. Three-line fix, same lock order as everywhere else (`routerLock → serviceLock`, so no inversion):

```go
func (s *Service) MarshalJSON() ([]byte, error) {
	s.serviceLock.RLock()
	defer s.serviceLock.RUnlock()
	...
}
```

---

## 8. New files

`service.go` is **863 lines**, already over the 800-line ceiling in `.claude/rules/coding-style.md`. `router_test.go` is over it too. Nothing substantial goes in either.

| File | Contents | ~lines |
|---|---|---|
| `internal/server/container_lifecycle.go` | `ContainerLifecycle` interface + sentinel errors — the swap seam | 45 |
| `internal/server/docker_client.go` | Socket-only Docker client, zero external deps | 195 |
| `internal/server/idle_controller.go` | State machine, coalescing, timer, backoff | 300 |
| `internal/server/service_idle.go` | The request gate, ref collection, suspend/resume, validation | 175 |

Tests: `idle_controller_test.go`, `docker_client_test.go`, `service_idle_test.go`, `router_idle_test.go`. Load-balancer tests go into the existing `load_balancer_test.go` (285 lines, room to grow).

Edits to existing files are surgical: `service.go` (+3 option fields, +4 struct fields, the gate call, `Dispose`, `UpdateLoadBalancer`, marshal/unmarshal, `RecheckTargetHealth` guard, `MarshalJSON` lock), `router.go` (`lifecycle` field, `SetContainerLifecycle`, preflight call, restore pass, `createOrUpdateService`, `describeServiceState`), `load_balancer.go` (2 methods + the `WaitUntilHealthy` lock), `target.go` (`ContainerRef`, `RestartHealthChecks`), `config.go`, `run.go`, `deploy.go`.

---

## 9. `internal/server/idle_controller.go` — the state machine

```go
// IdleState is where a service's containers are in the scale-to-zero cycle.
type IdleState int

const (
	IdleStateActive IdleState = iota
	IdleStateStopping
	IdleStateSleeping
	IdleStateWaking
)

var (
	ErrWakeTimeout          = errors.New("timed out waking containers")
	ErrWakeFailed           = errors.New("failed to wake containers")
	ErrNoContainerLifecycle = errors.New("scale-to-zero requires the proxy to run with --docker-socket")
	ErrNotAContainerRef     = errors.New("target does not name a container")
)

type IdleController struct {
	name      string
	lifecycle ContainerLifecycle

	// suspend takes the targets out of the pool and stops probing them; resume
	// puts them back and waits for them to answer. Supplied by the Service, so
	// the controller never reaches into a load balancer or its locks.
	suspend func()
	resume  func(timeout time.Duration) error
	persist func()

	lock        sync.Mutex
	state       IdleState
	generation  uint64
	refs        []string
	inflight    int
	lastRequest time.Time
	sleepAfter  time.Duration
	wakeTimeout time.Duration
	lastErr     error
	failures    int
	retryAfter  time.Time
	disabled    bool
	cancel      context.CancelFunc

	// changed is closed on every transition and then replaced. A waiter parks on
	// the channel it read under the lock and re-reads the state when it wakes,
	// so no decision is ever made from a stale snapshot. Nothing is ever sent on
	// it -- the close is the broadcast, exactly as in PauseController.
	changed chan struct{}

	signalled chan struct{} // buffered 1; nudges the timer goroutine
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *IdleController) setStateLocked(state IdleState) {
	if c.state == state {
		return
	}

	c.state = state
	c.generation++

	close(c.changed)
	c.changed = make(chan struct{})
}
```

`generation` replaces #228's per-wake `wakeDone` token and is strictly more general: **any** transition invalidates **any** in-flight lifecycle goroutine, and waiters never read a cached error because they re-derive under the lock on the next loop iteration.

### Transitions

| From | To | Trigger |
|---|---|---|
| Active | Stopping | timer fires, guard passes under the lock |
| Stopping | Sleeping | every `StopContainer` returned nil |
| Stopping | **Active** | any `StopContainer` errored — rollback, see below |
| Sleeping | Waking | `admit()` sees `Sleeping` past the backoff window |
| Waking | Active | every `StartContainer` nil **and** `resume()` nil |
| Waking | Sleeping | any start error, readiness failure, or deadline |
| any | Active | `Reset(refs)` — new active load balancer installed |
| Stopping/Waking | Sleeping | serialization, both directions |

### The hold and the coalescing

```go
// BeginRequest admits a request, waking the service first if it is asleep. It
// blocks the calling request goroutine and never touches the request, which is
// why the gate sits above target selection: the *http.Request handed on
// afterwards is byte-for-byte the one that arrived, body unread.
func (c *IdleController) BeginRequest(ctx context.Context) error {
	// One deadline for the whole call. Upstream allocated a fresh timer on every
	// loop iteration, so a request arriving while the service was still stopping
	// could wait the full wake timeout for the stop and the full wake timeout
	// again for the start -- twice the documented bound.
	deadline := time.Now().Add(c.WakeTimeout())

	for {
		changed, err := c.admit()
		if changed == nil {
			return err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrWakeTimeout
		}

		timer := time.NewTimer(remaining)
		select {
		case <-changed:
			timer.Stop()
		case <-timer.C:
			return ErrWakeTimeout
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.closed:
			timer.Stop()
			return ErrWakeFailed
		}
	}
}

// admit either takes a slot for the request, or hands back the channel to wait
// on for the next transition. A nil channel means the caller is done: admitted
// when err is nil, rejected otherwise.
func (c *IdleController) admit() (<-chan struct{}, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch c.state {
	case IdleStateActive:
		c.inflight++
		c.lastRequest = time.Now()
		return nil, nil

	case IdleStateSleeping:
		if time.Now().Before(c.retryAfter) {
			// A wake failed recently. Fail now rather than hold for the full
			// timeout and issue another doomed docker start: at request rate
			// that is an unbounded retry storm against the daemon.
			return nil, c.lastErr
		}
		c.startWakeLocked()
	}

	return c.changed, nil
}

func (c *IdleController) EndRequest() {
	c.lock.Lock()
	if c.inflight > 0 {
		c.inflight--
	}
	// Stamped on the way out as well as in, so an hour-long SSE stream counts as
	// activity for that hour rather than for the instant it started.
	c.lastRequest = time.Now()
	c.lock.Unlock()

	c.signal()
}
```

**Coalescing is a consequence of the mutex, not of extra machinery.** `startWakeLocked` is reachable only from the `Sleeping` arm, and its first statement flips the state to `Waking` while still holding `c.lock`. Concurrent callers serialize on that mutex: the first starts the wake, every later one falls through to `return c.changed, nil` and parks on one channel. **Twenty concurrent requests, exactly one `StartContainer`.**

```go
func (c *IdleController) startWakeLocked() {
	c.setStateLocked(IdleStateWaking)

	generation := c.generation
	refs := slices.Clone(c.refs)
	deadline := time.Now().Add(c.wakeTimeout)
	lifecycle, resume := c.lifecycle, c.resume

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	c.cancel = cancel

	slog.Info("Waking service", "service", c.name, "containers", refs)

	go func() {
		defer cancel()

		var err error
		for _, ref := range refs {
			// Starting an already-running container answers 304, which the
			// client treats as success. That is what lets a proxy whose state
			// file said "sleeping" for a container that never stopped heal
			// itself on the very next request.
			if startErr := lifecycle.StartContainer(ctx, ref); startErr != nil {
				err = fmt.Errorf("%w: container %s: %w", ErrWakeFailed, ref, startErr)
				break
			}
		}

		if err == nil && resume != nil {
			// Started is not ready. Wait on whatever budget the starts left,
			// not a fresh one.
			if remaining := time.Until(deadline); remaining <= 0 {
				err = ErrWakeTimeout
			} else {
				err = resume(remaining)
			}
		}

		c.finishWake(generation, err)
	}()
}

func (c *IdleController) finishWake(generation uint64, err error) {
	c.lock.Lock()

	// A deploy or a close landed mid-wake and has already decided what the state
	// should be. Do not overwrite it with the outcome of a wake it superseded.
	if c.generation != generation {
		c.lock.Unlock()
		return
	}

	c.cancel = nil
	suspend, persist := c.suspend, c.persist

	if err == nil {
		c.lastErr, c.failures, c.retryAfter = nil, 0, time.Time{}
		c.lastRequest = time.Now()
		c.setStateLocked(IdleStateActive)
	} else {
		c.lastErr = err
		c.failures++
		c.retryAfter = time.Now().Add(wakeBackoff(c.failures))
		c.setStateLocked(IdleStateSleeping)
	}
	c.lock.Unlock()

	if err != nil {
		slog.Error("Failed to wake service", "service", c.name, "error", err)
		// Back out of the pool, so a container that came up but never answered
		// is not probed once a second until somebody notices.
		if suspend != nil {
			suspend()
		}
		return
	}

	slog.Info("Service awake", "service", c.name)
	if persist != nil {
		persist()
	}
}

// wakeBackoff spaces out attempts after a failed wake. Without it a service
// whose container reference no longer resolves costs one docker start per
// inbound request, forever. Same shape as the dynamic-domain quarantine.
func wakeBackoff(failures int) time.Duration {
	return min(time.Second<<min(failures-1, 5), 30*time.Second)
}
```

### Sleep, with rollback

```go
func (c *IdleController) trySleep() {
	c.lock.Lock()
	if c.disabled || c.state != IdleStateActive || c.inflight != 0 ||
		c.sleepAfter <= 0 || c.lifecycle == nil || len(c.refs) == 0 ||
		time.Since(c.lastRequest) < c.sleepAfter {
		c.lock.Unlock()
		return
	}

	c.setStateLocked(IdleStateStopping)
	generation := c.generation
	refs := slices.Clone(c.refs)
	lifecycle, suspend, resume, persist := c.lifecycle, c.suspend, c.resume, c.persist
	c.lock.Unlock()

	slog.Info("Sleeping idle service", "service", c.name, "containers", refs)

	// Out of the pool before the containers go down, so nothing probes a
	// container on its way to stopped and nothing is routed to one that already
	// is. Requests arriving now see Stopping and are held by BeginRequest, so an
	// empty pool is never observable.
	if suspend != nil {
		suspend()
	}

	// No request waits on a stop, so it gets its own fixed budget rather than
	// the wake timeout. Docker's own stop is SIGTERM then SIGKILL after 10s.
	ctx, cancel := context.WithTimeout(context.Background(), containerStopTimeout)
	defer cancel()

	var stopErr error
	for _, ref := range refs {
		if err := lifecycle.StopContainer(ctx, ref); err != nil {
			slog.Error("Failed to stop idle container", "service", c.name, "container", ref, "error", err)
			stopErr = err
		}
	}

	c.lock.Lock()
	superseded := c.generation != generation
	if !superseded {
		if stopErr == nil {
			c.setStateLocked(IdleStateSleeping)
		} else {
			// Upstream marked the service asleep anyway, which turns an unmounted
			// socket or a pruned container into a permanent outage: every later
			// request held for the wake timeout and then 503'd, for containers
			// that are running perfectly. Roll back instead and push the next
			// attempt out by a full idle period.
			c.lastRequest = time.Now()
			c.setStateLocked(IdleStateActive)
		}
	}
	c.lock.Unlock()

	if superseded {
		return
	}

	if stopErr != nil {
		// Health checks sort out reality: containers that did stop stay out of
		// the pool, ones still running rejoin.
		if resume != nil {
			if err := resume(containerStopTimeout); err != nil {
				slog.Error("Failed to restore targets after a failed sleep", "service", c.name, "error", err)
			}
		}
		return
	}

	if persist != nil {
		persist()
	}
}
```

Suspend-before-stop is what makes the uniform rollback safe: because the gate holds arriving requests in `Stopping`, the empty pool is never observable, and on any stop error `ResumeFromSleep` re-probes and the truth reasserts itself. That is strictly better than partial-failure bookkeeping.

### Timer

```go
// run is the single idle timer. A service that cannot sleep right now parks for
// an hour and is nudged by signal() the moment anything changes, so an active
// service costs one timer, not one tick per second.
func (c *IdleController) run() {
	for {
		c.lock.Lock()
		wait := c.sleepAfter - time.Since(c.lastRequest)
		eligible := !c.disabled && c.state == IdleStateActive && c.inflight == 0 &&
			c.sleepAfter > 0 && len(c.refs) > 0
		c.lock.Unlock()

		if !eligible {
			wait = time.Hour
		}
		wait = max(wait, 0)

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			c.trySleep()
		case <-c.signalled:
			timer.Stop()
		case <-c.closed:
			timer.Stop()
			return
		}
	}
}
```

Go 1.26 — `timer.Stop()` alone is sufficient, no drain.

---

## 10. Behavior matrix

| Event | Result |
|---|---|
| **deploy while sleeping** | `createLoadBalancer` health-checks the **new** containers (router.go:550), `UpdateLoadBalancer` calls `Reset(refs)` under the service write lock → Active, backoff cleared. Held waiters are released and **loop back into `admit()`**, see Active, proceed. They are never told "the wake succeeded" — #228's `Reset` released them with a nil error, which is a lie under `deploy --force`, where nothing was health-checked. |
| **pause / stop while sleeping** | Requests never reach the gate: `handlePausedAndStoppedRequests` (service.go:768) runs first. So **no wake-side interlock is needed.** I *do* ship `Disable()`/`Enable()`, and it suppresses **sleeping only** — pause is a short window during a deploy, and letting the timer stop containers inside it turns a 2-second pause into a cold start on resume. `Enable()` resets `lastRequest` so a resumed service gets a full idle period. See §12 — this is a judgment call. |
| **wake timeout** | 503 through the service's own `--error-pages`, `Retry-After: 1`, backoff armed, containers left **running** so an operator has something to `docker logs`. |
| **Docker failure on start** | Same 503. `suspend()` re-runs so nothing probes a half-started container. Raw daemon error **logged, never rendered** (§11). |
| **Docker failure on stop** | Stays **Active**, `resume()` rolls the pool back, next attempt a full `--sleep-after` away. The §3 preflight makes this rare. |
| **health check never passes after wake** | `resume` → `WaitUntilHealthy` → `ErrorTargetFailedToBecomeHealthy` → wake fails → 503 + backoff. |
| **proxy restart mid-wake or mid-stop** | State serializes as `sleeping`. Next request issues `docker start` → `304` for whatever never stopped → `WaitUntilHealthy` passes on the first probe → Active. Self-healing. |
| **client hangs up mid-wake** | `BeginRequest` returns `ctx.Err()`; handler returns silently, no error page. The wake runs on a **detached** deadline context and completes for everyone else. |
| **two proxy generations during `kamal proxy reboot`** | Both may hold the service Active; the loser can `docker stop` a container the winner is serving. Inherent to two proxies against one daemon; the same window already exists for `--recheck-targets-on-restore`. Mitigated by `--drain-timeout` ordering, not by this code. |

---

## 11. Request gate — `service_idle.go`

```go
// handleIdleRequest holds the request until this service's containers are back.
// It returns whether the client has already been answered, and the function that
// releases the request's hold on the idle timer.
func (s *Service) handleIdleRequest(w http.ResponseWriter, r *http.Request) (bool, func()) {
	controller := s.idleController
	if controller == nil {
		return false, nil
	}

	// A TLS on-demand probe is synthesized inside the proxy and must never start
	// a container. validateSleep refuses --sleep-after with an on-demand URL, so
	// this only guards a state file written before that rule existed.
	if isInternalRequest(r) {
		return false, nil
	}

	// A health check must never wake a service -- an uptime monitor polling /up
	// would pin it awake forever -- and must be answered rather than held, or a
	// downstream load balancer evicts a service that is sleeping correctly.
	if s.targetOptions.IsHealthCheckRequest(r) {
		return s.answerIdleHealthCheck(w, r, controller), nil
	}

	if err := controller.BeginRequest(r.Context()); err != nil {
		if errors.Is(err, context.Canceled) {
			// The client hung up mid-wake. Nobody left to answer.
			return true, nil
		}

		// Logged, not rendered. The underlying error carries container
		// references and up to four kilobytes of daemon output, and this
		// response is reachable by anyone who can open a connection.
		slog.Error("Rejecting request: service did not wake",
			"service", s.name, "path", r.URL.Path, "error", err)
		w.Header().Set("Retry-After", "1")
		SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
		return true, nil
	}

	return false, controller.EndRequest
}

// answerIdleHealthCheck answers for a sleeping service without waking it. It
// reports healthy while the sleep is working as intended and stops the moment a
// wake has actually failed -- upstream returned 200 unconditionally, so a
// service that could no longer start reported green to its monitoring forever
// while 503ing every real request.
func (s *Service) answerIdleHealthCheck(w http.ResponseWriter, r *http.Request, controller *IdleController) bool {
	if controller.State() == IdleStateActive {
		return false
	}

	if err := controller.LastWakeError(); err != nil {
		slog.Warn("Reporting unhealthy: last wake failed", "service", s.name, "error", err)
		SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
		return true
	}

	w.WriteHeader(http.StatusOK)
	return true
}
```

Controller construction writes `s.idleController` **once** per `Service` lifetime and reconfigures in place thereafter, so the request path's unlocked read is safe by construction:

```go
func (s *Service) configureIdleController(options ServiceOptions) {
	if options.SleepAfter <= 0 {
		if s.idleController != nil {
			s.idleController.Configure(0, 0, nil)
		}
		return
	}

	if s.idleController == nil {
		if s.lifecycle == nil {
			// DeployService refuses --sleep-after without a lifecycle, so this is
			// a restored service whose lifecycle arrives later, from
			// SetContainerLifecycle. Building the controller now would start a
			// timer that could reach StopContainer on a nil interface.
			return
		}
		s.idleController = NewIdleController(
			s.name, s.lifecycle, s.suspendForSleep, s.resumeFromSleep, s.persistState)
		s.idleController.Restore(s.restoredIdleState)
	}

	s.idleController.Configure(options.SleepAfter, options.WakeTimeout, s.containerRefs(options))
}
```

Called as the last line of `initialize` (service.go:571). `Dispose` gains `if s.idleController != nil { s.idleController.Close() }`.

**`internal/cmd/util.go` needs no change** — `getEnvString` already exists at util.go:79, so #228's hunk is a duplicate declaration.

---

## 12. TDD list, in write order

Each entry: the test, then the one behavior it proves.

**Controller — `idle_controller_test.go`, `fakeLifecycle` counting `atomic.Int64`, no HTTP**

1. `TestIdleState_NamesRoundTrip` — `stopping`/`waking` parse back to `sleeping`; unknown → `active`. *Locks the persisted vocabulary before anything writes it.*
2. `TestIdleController_AdmitsRequestsWhileActive` — `BeginRequest` returns nil, zero lifecycle calls. *The feature costs nothing when awake.*
3. `TestIdleController_SleepsAfterIdlePeriod` — one `StopContainer` per ref, `suspend` called, state `sleeping`, `persist` once.
4. `TestIdleController_DoesNotSleepWithRequestsInFlight` — `BeginRequest` without `EndRequest` ⇒ no stop, ever. *The WebSocket/SSE guarantee at unit level.*
5. `TestIdleController_WakesOnTheNextRequest` — one `StartContainer`, `resume` called with a positive budget, state `active`.
6. `TestIdleController_CoalescesConcurrentWakes` — 20 goroutines, `starts.Load() == 1`, all 20 return nil. *The headline property; the one thing that must never regress.*
7. `TestIdleController_BoundsTheWaitAcrossAStopAndAWake` — a request arriving during `Stopping` with a blocking stop returns by `wakeTimeout`, not 2×. *Proves the single-deadline fix.*
8. `TestIdleController_ClientCancellationReleasesTheWaiterNotTheWake` — cancelled ctx returns `context.Canceled` while the wake completes; a later call finds `active`.
9. `TestIdleController_BacksOffAfterAFailedWake` — three sequential `BeginRequest`s against a failing lifecycle ⇒ exactly one `StartContainer`; calls 2 and 3 return the cached error immediately. *Proves no request-rate retry storm.*
10. `TestIdleController_StaysAwakeWhenContainersCannotBeStopped` — stop errors ⇒ state `active`, `resume` called, no persist. ***The most important test in the suite** — the exact inverse of #228's `TestIdleControllerRecoversFromPartialStopFailure`.*
11. `TestIdleController_ResetSupersedesAnInFlightWake` — `Reset` during a slow wake; waiters proceed, and the wake's late `finishWake` does not move the state. *The generation token.*
12. `TestIdleController_DisableSuppressesSleepOnly` — disabled + idle ⇒ no stop; a request still wakes a sleeping service.
13. `TestIdleController_PersistsOnlySleepAndWakeEdges` — persist count is exactly 2 per cycle.

**Docker client — `docker_client_test.go`, `httptest` over a real unix listener**

14. `TestDockerClient_NegotiatesAndUsesVersionedPaths` — `POST /v1.44/containers/web-1/start`, name path-escaped. *The wire contract.*
15. `TestDockerClient_TreatsNotModifiedAsSuccess` — `304` is not an error. *A coalesced wake against a running container succeeds.*
16. `TestDockerClient_FallsBackWhenVersionIsUnavailable` — transport error and non-2xx both yield `1.41`. *Socket proxies without `/version` still work.*
17. `TestDockerClient_DoesNotCacheANegotiationFailure` — call twice, second succeeds. *Fixes #228's permanently-poisoned cache.*
18. `TestDockerClient_TruncatesLongErrorBodies` and `_ReadsALargeVersionPayload` — 4 KB error cap; `/version` gets its own much larger limit. *A plugin-heavy host does not truncate into `unexpected EOF`.*
19. `TestDockerClient_ClassifiesMissingAndForbidden` — 404 → `ErrContainerNotFound`, 403 → `ErrContainerInspectForbidden`. *Drives the preflight's warn-vs-fail split.*

**Target and load balancer**

20. `TestTarget_ContainerRefRejectsAddresses` — table: `web-1`→ok, `3f2a1b9c4d5e`→ok, `web-1:3000`→`web-1`, `web-1:3000;weight=5`→`web-1`, `10.0.0.5:3000`→false.
21. `TestLoadBalancer_SuspendForSleepEmptiesThePoolAndStopsProbing` — `HealthyTargets()` empty; killing the backend produces no further state churn.
22. `TestLoadBalancer_ResumeFromSleepRearmsWaitUntilHealthy` — **against a single-target pool**, so the checks were already stopped at first-healthy: suspend, resume, `WaitUntilHealthy(time.Second)` returns nil only once the backend actually answers. *Proves the exact defect in §5 — without `ResumeFromSleep` this returns nil instantly.*
23. `TestLoadBalancer_ResumeFromSleepDoesNotReleaseAPreviousWaiter` — a `WaitUntilHealthy` already parked is **not** released by the resume. *The #228 booby trap, avoided.*

**Service — `service_idle_test.go`**

24. `TestServiceOptions_ValidateSleep` — table: negative durations, `--tls-on-demand-url`, `--sleep-container` without `--sleep-after`.
25. `TestService_SleepingServiceWakesAndForwardsAChunkedBody` — POST with `Transfer-Encoding: chunked` and no `Content-Length`; backend receives every byte. ***The headline behavioral test.***
26. `TestService_BlockedRequestsDoNotWake` — table over `--allow-ip`, `--basic-auth`, `--rate-limit`, canonical-host redirect: each returns its own status with `starts.Load() == 0`. ***Proves the placement decision; the reason this is a port and not a `git apply`.***
27. `TestService_HealthCheckDoesNotWake` / `TestService_HealthCheckReportsUnhealthyAfterAFailedWake` — the two halves of the monitoring-honesty fix.
28. `TestService_StreamingResponsePreventsSleep` — an SSE handler held open past `--sleep-after` ⇒ no stop; closing it lets the next tick sleep. *End-to-end §4.*
29. `TestService_WakeFailureRendersTheServicesErrorPage` — custom `--error-pages` 503 body, **and assert the container reference does not appear in it**.
30. `TestService_PausedServiceIsNeverWokenByTraffic`.
31. `TestService_SleepStateSurvivesAMarshalRoundTrip` / `TestService_StateFileWithoutIdleStateRestoresAwake` — forward and backward compatibility.

**Router — `router_idle_test.go`**

32. `TestRouter_DeployRejectsSleepAfterWithoutADockerSocket` — `ErrNoContainerLifecycle`.
33. `TestRouter_DeployRejectsAnUnknownContainer` / `_RejectsAnAddressTarget` — both error messages name `--sleep-container`.
34. `TestRouter_DeployWarnsButProceedsWhenInspectIsForbidden` — the hardened-socket-proxy path.
35. `TestRouter_SleepContainerOverridesInference` — `--sleep-container` set ⇒ target hostnames never consulted.
36. `TestRouter_RestoreSuspendsASleepingServicesTargets` — `HealthyTargets()` empty after restore despite `MarkAllHealthy`.
37. `TestRouter_ListShowsSleepingAndPrefersPaused`.

**CLI**

38. `TestDeployCommand_SleepFlags` (defaults `0` / `30s` / nil), `TestRunCommand_DockerSocketFlagDefaultsToDisabled`, `_RejectsAMissingSocket`.

Then: `gofmt -l internal/ cmd/`, `make test`, and **`go test -race ./...` is mandatory** — this touches `Router`, `LoadBalancer` and `Target`.

No `make bench` gate: `BeginRequest` on an active service is one uncontended mutex acquire. I would still add `BenchmarkService_ServeHTTPWithIdleControllerActive` against the same service without one, since the gate is on every request of a sleep-enabled service.

---

## 13. What I am NOT confident about

**1. The prune interaction is unfixed and unfixable from this side.** Verified: `kamal deploy` invokes `kamal:cli:prune:all` on every run (`kamal/lib/kamal/cli/main.rb:58`), and `Kamal::Commands::Prune#app_containers` (`prune.rb:16-21`) pipes `docker ps -q -a --filter status=exited …` through `tail -n +6` into `docker rm`. **A sleeping container is `exited`.** With more than five stopped containers for a service, a sleeping one is a `docker rm` candidate — after which the persisted reference names nothing, every wake 404s, backoff climbs to 30s, and the service 503s permanently. The deploy preflight proves the ref resolves *at deploy time* and cannot prevent this. The backoff (test 9) and the honest health check (test 27) turn it from a silent outage into a visible one; they are mitigation, not a fix. **The real fix is gem-side** — exclude proxy-managed containers from the prune filter, or have the gem pass a stable label selector. It belongs in `../kamal` as a follow-up and must be named in the PR body and `ROADMAP.md`, as the PROXY-protocol and weighted-target work did.

**2. The preflight is a new way for a deploy to fail.** In Kamal the target ID and the proxy's socket are the same host and daemon, so it holds. In a DinD, remote-daemon, or split-daemon socket-proxy topology, `ContainerExists` 404s and **every `--sleep-after` deploy fails loudly** — better than #228's silent outage, but new, and it fails on the RPC path where a hung socket costs `containerPreflightTimeout`. The 403 warn-path covers hardened socket proxies; it does not cover wrong-daemon. I considered a `--skip-sleep-preflight` escape hatch and left it out as YAGNI. **Revisit if anyone reports it.**

**3. `Disable()` on pause is a judgment call, not a derivation.** Plan 2 argued for shipping nothing (the pause gate makes the wake half unreachable — true, verified). I ship the sleep half because a pause during a deploy that lets containers stop turns a 2-second window into a cold start. But `kamal-proxy stop` arguably *should* stop containers. I chose "suppress sleeping in both paused and stopped" for uniformity. **Low confidence; cheap to flip; make it a review question.**

**4. `Service.MarshalJSON` taking `serviceLock.RLock()` is a pre-existing-race fix bundled into a feature PR.** Lock order is safe (`routerLock → serviceLock`, matching `installLoadBalancer`), and I verified no inversion. But it is a behavior change to the save path that this feature merely makes reachable, and a reviewer may reasonably want it split into its own commit. **I would land it as a separate first commit on the same branch.**

**5. `RestartHealthChecks` does not fix the pre-existing `stateConsumer` race**, it only avoids widening it. `BeginHealthChecks` writes `t.stateConsumer` outside `withInflightLock` (target.go:285) while a live healthcheck goroutine can read it in `HealthCheckCompleted` (target.go:340). `RecheckHealth` already reaches this at runtime. My design routes the new wake path around it rather than through it — but `-race` may surface the existing one via `--recheck-targets-on-restore` tests once more of this code runs concurrently. **If it does, the fix is moving the assignment inside the lock, and it is in scope.**

**6. Unmeasured:** `resume()` bounds a wake by a health-check round trip, so the cold-start figure depends entirely on the app. #228 measured 3.15s for a real Rails boot on a VPS; I have not reproduced that here and **the PR must not repeat the number as if this implementation had been measured.**