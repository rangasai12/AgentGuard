# Contributor conventions

This file records the rules that keep the codebase from growing two versions of
the same thing. It is short on purpose. Read it before adding anything.

## The rule: no second implementation of anything that already exists

Before adding a function, type, table, endpoint, page, protocol command, or test
fake:

1. **Name the closest existing symbol.** Check the registry below first, then
   grep. If something already does most of the job, extend it.
2. **Write the justification before the code.** The CHANGELOG entry for the
   milestone gets a `### Guardrail: why new code` section that names the closest
   existing symbol and states why it cannot be extended with a small change. If
   you cannot write that paragraph convincingly, extend the existing symbol.
3. **Check at the end of the milestone** that every new name has exactly one
   definition:

   ```
   grep -rn "func NewThing\|type NewThing\|class NewThing\|export function newThing" \
     --include=*.go --include=*.py --include=*.ts . | grep -v _test | wc -l   # expect 1
   ```

   and run the dead-code pass on touched packages (`go vet ./...`, `pyflakes` on
   `sdk-python`, and a cross-reference of exported TypeScript symbols), as done
   in the CHANGELOG's "Dead-code audit" entry.

Concretely forbidden: a second audit-event struct, a second decision funnel, a
second socket client per language, a second event-ingest endpoint, a second
events table, a second polling hook, a second webhook sender, a second time-range
parser, a second adapter base pattern, a second daemon test fake per language, a
second tenant-settings table or page, a second tool table, a second metrics/aggregation function, a second resource-normalization rule.

## Canonical symbol registry ("one of each")

| Concern | The one place it lives |
|---|---|
| Audit event shape | `daemon.AuditEvent` (`daemon/audit.go`) |
| Policy decision + approval wait + audit write | `daemon.Decide` (`daemon/daemon.go`) — every enforcement point calls it |
| Post-execution outcome write | `daemon.AuditLogger.Report` (`daemon/audit.go`) |
| Random hex ids | `daemon.newHexID` (`daemon/approval.go`) |
| Daemon socket client, Go | `cli.Client` (`cli/client.go`) |
| Daemon socket client, Python | `agentguard.DaemonClient` (`sdk-python/agentguard/client.py`) |
| Daemon socket client, TypeScript | `DaemonClient` (`sdk-ts/src/client.ts`) |
| Daemon test fake, Go | `testClient` + `startTestServer` (`daemon/socket_api_test.go`) |
| Daemon test fake, Python | `FakeDaemon` + `decision_handler` (`sdk-python/tests/conftest.py`) |
| Daemon test fake, TypeScript | `FakeDaemon` + `decisionHandler` (`sdk-ts/test/fakeDaemon.ts`) |
| Tool-call wrapping, Python | `Guard._wrap_one` / `_wrap_attr` (`sdk-python/agentguard/guard.py`) |
| Tool-call wrapping, TypeScript | `Guard.wrapOne` / `wrapAttr` (`sdk-ts/src/guard.ts`) |
| Decide → deny-or-run → report, Python | `Guard._decide` / `_guarded_call` / `_execute` / `_report`, built into wrappers by `_wrap_callable` (`guard.py`) — nothing else talks to the daemon |
| Decide → deny-or-run → report, TypeScript | `Guard.decide` / `guardedCall` / `execute` / `report` (`guard.ts`) — adapters call `checkAndExecute`, never re-check |
| Argument capture for the audit trail | `_capture_args` / `_bind_args` (Python), `captureArgs` / `positionalArgs` (TS) |
| Audit query filter flags (CLI) | `addAuditFilterFlags` (`cli/audit_cmd.go`), shared by `audit query` and `policy record` |
| Audit → trace-file conversion | `runPolicyRecord` (`cli/policy_cmd.go`) writing `engine.TestSuite`, the same shape `policy test` reads |
| Duck-typed field access in adapters | `adapters/_compat.get_field` (Python), `adapters/compat.getField` (TS) |
| Event ingest endpoint | `POST /v1/events` → `handleIngestEvents` (`dashboard/server/controlapi.go`) |
| Events table | `audit_events` (`dashboard/store/schema.sql`) |
| Event query WHERE builder | `store.QueryEvents` (`dashboard/store/events.go`) |
| Aggregated stats (overview, per-agent profile, per-version, anomaly windows) | `store.Metrics` + `store.MetricsFilter` (`dashboard/store/events.go`) |
| Resource grouping key ("footprint") | `engine.ScopeKey` (`engine/scope.go`), stored as `audit_events.scope_key` at ingest |
| Tool catalog (descriptions, and from Phase 4 verb classes) | `tool_catalog` table, upserted by `store.InsertEvents`, read by `store.ListToolCatalog` |
| Tool description capture | `Guard.remember_description` / `_remember_tool` (Python), `Guard.rememberDescription` / `rememberTool` (TS), `Proxy.rememberDescriptions` (MCP); attached once per tool by `_with_description` / `withDescription` / `descriptionFor` |
| Automatic agent version | `_git_head_version` + `_freeze_version` (Python), `gitHeadVersion` + `freezeVersion` (TS) |
| Shared stat card / ranked list | `components/StatCard.tsx`, `components/RankList.tsx` |
| Per-agent profile UI | `AgentDetailPanel` inside `pages/AgentsPage.tsx` (no separate page) |
| Time-range query parsing | `server.parseTimeParam` (`dashboard/server/timeparam.go`) |
| Webhook/Slack sender | `daemon.WebhookNotifier` (`daemon/webhook.go`) |
| Approval wait seam | `daemon.Awaiter` + `daemon.PromptAwaiter` (`daemon/daemon.go`) |
| Argument redaction | `engine.Policy.RedactArgs` (`engine/policy.go`), applied only inside `daemon.Decide` |
| Frontend data fetching | `usePolling` (`dashboard/web/src/hooks/usePolling.ts`) |
| Status pill (decision or outcome) | `DecisionBadge` (`dashboard/web/src/components/DecisionBadge.tsx`) |
| Frontend API client | `api` (`dashboard/web/src/api/client.ts`) |
| Frontend types | `dashboard/web/src/api/types.ts` (mirrors `store/models.go`) |
| Nav entries | `Sidebar.tsx NAV_GROUPS` + `Header.tsx PAGE_LABELS` + `App.tsx` routes, changed together |
| Tool-call verb classification | `engine.HeuristicVerb` (`engine/verb.go`, every built-in action type and the LLM's fallback); `server.toolClassifier` (`dashboard/server/classifier.go`, the one caller of the OpenAI Chat Completions API) |
| Local `.env` loading (cloud binary only) | `loadDotEnv` (`cmd/agentguard-cloud/main.go`) |
| Anomaly detection | `server.anomalyRunner` (`dashboard/server/anomaly.go`) — one detector, four kinds (system/operation/scope/volume), reusing `store.Metrics` for every rate/count it needs plus four narrow aggregates (`store.VerbCounts`, `RunEventCounts`, `ScopeOutputStats`, `NewScopeKeys`) that `Metrics`/`topN` cannot express |
| Anomalies table + API | `anomalies` table, `store.Anomaly` + `UpsertAnomaly`/`ListAnomalies`/`AckAnomaly`, `GET /api/anomalies` + `POST /api/anomalies/ack` |
| Tenant anomaly-detection settings | `tenant_settings` table, `store.TenantSettings` + `DefaultTenantSettings`, `GET/PUT /api/settings`, `SettingsPage.tsx` |
| Anomaly list UI | `components/AnomalyList.tsx` (used by `OverviewPage` and the Fleet `AgentDetailPanel` — never re-rendered inline in either) |

Update this table when a canonical symbol is added or renamed.

## CHANGELOG entry template

Every milestone appends one entry to `CHANGELOG.md`:

```
## <title> — <one-line detail>

### Why
### What changed
### Guardrail: why new code
### Deferred / known gaps
### Verification run at this milestone
```

The verification section lists the actual commands run and their real results.
Gaps are recorded, never omitted.

## Running the tests

**Before running the Go tests, point them at a dedicated test database —
never the one a dev server or a manually-registered agent is using.**
`dashboard/store`/`dashboard/server` tests default to
`postgres:///agentguard_dashboard_dev` when `AGENTGUARD_DASHBOARD_TEST_DB`
is unset, and every test truncates every table (`Store.ResetForTests`)
before it runs. Running the suite against the same database a dev
`agentguard-cloud` is serving wipes every tenant/agent/event in it,
including anything registered through the real UI/forwarder — this has
happened more than once in this project's history. Create a separate
database once (`createdb agentguard_dashboard_test`) and export the
variable for every test invocation:

```
export AGENTGUARD_DASHBOARD_TEST_DB=postgres:///agentguard_dashboard_test
go test -p 1 ./...        # -p 1: dashboard packages share one real Postgres test DB
cd sdk-python && pytest
cd sdk-ts && npm test
cd dashboard/web && npm run build
```
