# Upstream Sync — Retired (Historical Note)

**There is no upstream sync anymore.** As of the 2026-08 clean break (zoolutions/dash#115),
dash-proxy left the basecamp/kamal-proxy fork network, the `upstream` remote was removed, and
the old `dash` integration branch was fast-forwarded into `main` and deleted. `main` is the
only long-lived branch; everything lands there via PR.

If a basecamp/kamal-proxy fix is ever wanted, cherry-pick it deliberately from a fresh clone
of their repo — do not re-add an `upstream` remote or resurrect the mirror-branch model.

What survives from the fork era (see `CLAUDE.md` Critical Rules):

- The Go module, binary, RPC service, socket, and `org.opencontainers.image.title=kamal-proxy`
  label keep their `kamal-proxy` names until the server-artifact rename ships a migration bridge.
- Release ordering is unchanged: publish `ghcr.io/zoolutions/dash-proxy:<tag>` FIRST, then point
  the dash gem's `MINIMUM_VERSION` at it.
- Tag grammar `vX.Y.Z.N` (plain `vX.Y.Z` accepted), never suffix tags, never `git push --tags`.
- The old `ghcr.io/zoolutions/kamal-proxy` package stays published — released gem versions pull it.
