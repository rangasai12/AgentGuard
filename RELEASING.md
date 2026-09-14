# Releasing

AgentGuard is pre-1.0 (`0.x`). Per semver, **breaking changes are possible
between any two minor versions until 1.0.0** — there is no compatibility
guarantee yet across the three packages (`agentctl`/the Go module, the
Python SDK, the TypeScript SDK). This is a deliberate, stated policy, not
an oversight: the project is young (see `CHANGELOG.md` for the full build
history) and would rather say so plainly than imply a stability it hasn't
earned. Post-1.0, this file's policy switches to standard semver
(breaking changes only on a major bump).

## The three packages and where their version lives

| Package | Version lives in | Installed as |
|---|---|---|
| CLI (`agentctl`) | a git tag (`vX.Y.Z`) — the Go module itself is unversioned between tags | `go install github.com/rangasai12/AgentGuard/cli/cmd/agentctl@vX.Y.Z` (or `@latest`) |
| Python SDK | `sdk-python/pyproject.toml`'s `version` | `pip install agentguard` |
| TypeScript SDK | `sdk-ts/package.json`'s `version` | `npm install agentguard` |

The three have historically moved together (see the `CHANGELOG.md` phase
entries) but nothing enforces that they must — bump only what actually
changed.

## Cutting a release

1. Decide the new version. Bump the patch/minor number for whichever
   package(s) changed (`sdk-python/pyproject.toml`'s `version`,
   `sdk-ts/package.json`'s `version`); leave the others untouched if they
   didn't change.
2. Make sure `CHANGELOG.md` has an entry for the work being released (it
   should already, per `docs/conventions.md`'s process — this step is a
   check, not new writing).
3. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag version should
   match whichever package(s) actually changed; if only the Python SDK
   moved, the tag is still what `go install ...@vX.Y.Z` and the CLI
   release binaries key off, so tag every release even if the CLI itself
   didn't change.
4. Run the publish workflows for whatever changed
   (`.github/workflows/publish-python.yml`, `publish-npm.yml`,
   `publish-cli.yml`), each a manual `workflow_dispatch` — see their
   descriptions for the one-time secrets setup (`PYPI_TOKEN`, `NPM_TOKEN`)
   they need before they can actually publish anything.

## What's not automated

Nothing here bumps version numbers for you, and no workflow runs on a
plain push to `main` except the test suite (`test.yml`) — publishing is
always an explicit, manual `workflow_dispatch` so a release is never a
side effect of merging.
