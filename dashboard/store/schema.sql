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
