-- Schema for the AgentGuard Cloud dashboard (Phase 1).
--
-- IDs are app-generated random hex strings (see store/ids.go), not
-- Postgres-generated UUIDs, so this schema needs no extensions and stays
-- portable across any Postgres 13+ instance.
--
-- Every table below except `tenants`/`users`/`sessions` carries tenant_id,
-- and every query in dashboard/store derives tenant_id from the
-- authenticated caller (session for a user, API key for an agent) rather
-- than trusting a client-supplied value — see store/events.go and
-- store/pending.go for where that scoping is enforced.

CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS memberships (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role      TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    PRIMARY KEY (user_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- One row per registered agent (an agentguard-forwarder instance on a
-- customer's machine). `registration_token_hash` is single-use: it's set
-- when a tenant admin adds an agent from the dashboard, and cleared once
-- the forwarder redeems it for an api_key_hash via POST /v1/agents/register.
CREATE TABLE IF NOT EXISTS agents (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN ('pending', 'active')) DEFAULT 'pending',
    registration_token_hash  TEXT,
    api_key_hash             TEXT,
    last_seen_at             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id);

-- One row per AuditEvent ingested from a forwarder. No uniqueness
-- constraint on the source event: the forwarder's file-offset checkpoint
-- (advanced only after a successful ingest ack) makes double-delivery rare
-- (a network blip between the server committing and the forwarder
-- persisting its new offset), and a Phase-1 decision to accept that rare
-- over-count rather than add a dedupe key. See CHANGELOG.md.
CREATE TABLE IF NOT EXISTS audit_events (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ts           TIMESTAMPTZ NOT NULL,
    actor        TEXT NOT NULL DEFAULT '',
    action_type  TEXT NOT NULL,
    resource     TEXT NOT NULL DEFAULT '',
    decision     TEXT NOT NULL,
    matched_rule TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    approval_id  TEXT NOT NULL DEFAULT '',
    latency_ms   BIGINT NOT NULL DEFAULT 0,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_ts       ON audit_events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_decision ON audit_events(tenant_id, decision);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_agent_ts ON audit_events(tenant_id, agent_id, ts DESC);

-- Columns added after the table above shipped, mirroring the fields
-- daemon.AuditEvent grew for run/version identity, the structured action,
-- and the execution outcome. Same idempotent applied-on-every-boot model as
-- everything else in this file: ADD COLUMN IF NOT EXISTS is a no-op once
-- the column exists, so this needs no migration runner.
--
-- event_id is the daemon's per-decision id (unique only within one
-- daemon, hence indexed together with agent_id). An outcome patch line
-- from the forwarder (kind = "outcome") does not insert a row; it UPDATEs
-- the decision row matching (tenant_id, agent_id, event_id) — see
-- store.InsertEvents.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_id      TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS run_id        TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS agent_version TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS policy_hash   TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS action        JSONB;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS outcome       TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS exec_ms       BIGINT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS output        TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS output_bytes  BIGINT NOT NULL DEFAULT 0;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS output_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS error         TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS reported_at   TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_audit_events_agent_event
    ON audit_events(agent_id, event_id) WHERE event_id <> '';
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_agent_version_ts
    ON audit_events(tenant_id, agent_id, agent_version, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_run
    ON audit_events(tenant_id, run_id) WHERE run_id <> '';

-- scope_key is engine.ScopeKey(action_type, resource) computed once at
-- ingest: the coarser grouping key the per-agent profile and the anomaly
-- detector both use for "what does this agent touch" (a directory rather
-- than a file, a program rather than a full command line). Rows ingested
-- before this column existed have '' and readers fall back to resource.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS scope_key TEXT NOT NULL DEFAULT '';

-- One row per named tool (mcp_tool / function actions only — built-in
-- action types have implied semantics and unbounded resource cardinality)
-- a tenant's agents have called, with the description the SDK or MCP proxy
-- sent on the tool's first call and the argument names seen. This is the
-- one tool table: the anomaly detector's verb classification (Phase 4)
-- adds its columns here rather than keeping a second registry.
CREATE TABLE IF NOT EXISTS tool_catalog (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_type   TEXT NOT NULL,
    resource      TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    arg_keys      JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, action_type, resource)
);

-- Verb classification columns (Phase 4): what coarse class of operation
-- (read/write/delete/permission/unknown) this tool performs, used by the
-- anomaly detector's "operation" kind to bucket calls by effect rather
-- than by name. verb_source records where the value came from so a human
-- override (verb_source = 'user') is never clobbered by a later
-- reclassification pass, which only ever touches rows with verb_source = ''.
ALTER TABLE tool_catalog ADD COLUMN IF NOT EXISTS verb            TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_catalog ADD COLUMN IF NOT EXISTS verb_reason     TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_catalog ADD COLUMN IF NOT EXISTS verb_confidence DOUBLE PRECISION;
ALTER TABLE tool_catalog ADD COLUMN IF NOT EXISTS verb_source     TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_catalog ADD COLUMN IF NOT EXISTS classified_at   TIMESTAMPTZ;

-- One row per tenant: the anomaly detector's thresholds, editable from the
-- Settings page. A tenant with no row here gets store.DefaultTenantSettings()
-- — there is no implicit insert, so "using the defaults" and "an admin
-- explicitly saved these exact numbers" stay distinguishable.
CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id           TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    window_minutes      INT NOT NULL DEFAULT 60,
    baseline_hours      INT NOT NULL DEFAULT 24,
    min_baseline_events INT NOT NULL DEFAULT 50,
    volume_ratio        DOUBLE PRECISION NOT NULL DEFAULT 3,
    share_shift         DOUBLE PRECISION NOT NULL DEFAULT 0.3,
    deny_rate_ratio     DOUBLE PRECISION NOT NULL DEFAULT 3,
    error_rate_ratio    DOUBLE PRECISION NOT NULL DEFAULT 3,
    latency_ratio       DOUBLE PRECISION NOT NULL DEFAULT 3,
    bulk_ratio          DOUBLE PRECISION NOT NULL DEFAULT 5,
    min_events          INT NOT NULL DEFAULT 5,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per detected deviation, keyed so re-running detection on the same
-- (agent, kind, key) within the same window updates the row in place
-- rather than duplicating it. `key` names what deviated within `kind`
-- (a scope key for "system"/"scope", a verb or "deny_rate" for
-- "operation", "events_per_hour"/"calls_per_run" for "volume").
CREATE TABLE IF NOT EXISTS anomalies (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id         TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    agent_version    TEXT NOT NULL DEFAULT '',
    kind             TEXT NOT NULL,
    key              TEXT NOT NULL,
    score            DOUBLE PRECISION NOT NULL DEFAULT 0,
    detail           JSONB NOT NULL DEFAULT '{}'::jsonb,
    window_start     TIMESTAMPTZ NOT NULL,
    window_end       TIMESTAMPTZ NOT NULL,
    baseline_start   TIMESTAMPTZ,
    baseline_end     TIMESTAMPTZ,
    baseline_version TEXT NOT NULL DEFAULT '',
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_by  TEXT REFERENCES users(id),
    acknowledged_at  TIMESTAMPTZ,
    UNIQUE (agent_id, kind, key, window_start)
);

CREATE INDEX IF NOT EXISTS idx_anomalies_tenant_detected ON anomalies(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_tenant_agent    ON anomalies(tenant_id, agent_id, detected_at DESC);

-- The most recent agent_version / policy_hash seen on an ingested event,
-- so the fleet view can show what each agent is currently running without
-- a separate heartbeat field.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_agent_version TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_policy_hash   TEXT NOT NULL DEFAULT '';

-- Mirrors daemon.PendingApproval, plus the tenant/agent scoping and the
-- resolution-relay bookkeeping the forwarder needs.
--
-- local_id is the daemon's own approval id (8 hex chars, unique only within
-- that one daemon) — never unique across agents, hence the composite
-- unique constraint below rather than using it as the primary key.
--
-- requested_resolution / status split: a browser click sets
-- requested_resolution (status stays 'pending') so the forwarder's poll of
-- GET /v1/pending/resolutions finds it; only after the forwarder confirms
-- it relayed the decision to the local daemon (POST /v1/pending/ack) does
-- status flip to 'approved'/'denied'. This makes "the browser click
-- succeeded" distinct from "the local daemon actually saw it" — the
-- former without the latter would be a lie about what's enforced.
CREATE TABLE IF NOT EXISTS pending_approvals (
    id                     TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id               TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    local_id               TEXT NOT NULL,
    actor                  TEXT NOT NULL DEFAULT '',
    action_type            TEXT NOT NULL,
    resource               TEXT NOT NULL DEFAULT '',
    matched_rule           TEXT NOT NULL DEFAULT '',
    reason                 TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'resolved_elsewhere')) DEFAULT 'pending',
    requested_resolution   TEXT CHECK (requested_resolution IN ('approve', 'deny')),
    resolved_by            TEXT REFERENCES users(id),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at            TIMESTAMPTZ,
    UNIQUE (agent_id, local_id)
);

CREATE INDEX IF NOT EXISTS idx_pending_tenant_status ON pending_approvals(tenant_id, status);
