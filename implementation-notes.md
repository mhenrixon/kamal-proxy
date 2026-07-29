# Implementation notes — #19 completion

## Deviations

## Discoveries

- `statePersister` was added in #65 (field + call site) but nothing ever set it, so
  sleep/wake state was never actually persisted. A defect in already-merged code,
  fixed here rather than left.

## Judgment calls

- `Configure` treats a changed container set as a redeploy and forces the state back
  to active. On a restored service the controller is brand new, so its refs always
  look changed -- which silently undid `RestoreSleeping` and brought a sleeping
  service back awake. Configure now runs BEFORE the restore, not after.

- The idle gate moved from `serviceRequestWithTarget` to `sendRequestToTarget`, i.e.
  below the response cache. A cache hit never reaches the target, so it must not
  spend a container start; serving cached responses while the container sleeps is
  the point of running both. Still below every auth/rate-limit/redirect gate and
  still above target selection, so nothing else changes.

## Judgment calls

- `persistState` logs its error rather than returning it. The controller has already
  moved by then, so a failed write costs a wrong state on the next boot, not a broken
  proxy now.
- Preflight timeout is 10s, on the RPC path where a hung socket holds the operator's
  terminal.
- `describeServiceState` puts pause/stop above sleeping/waking: a human decision
  outranks anything traffic-driven.
