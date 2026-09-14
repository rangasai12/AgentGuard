# AgentGuard Cloud API — Onboarding Reference

The dashboard's REST API (`dashboard/server/`) has no OpenAPI spec and, until
this page, no contract documented anywhere outside the frontend's own
`dashboard/web/src/api/client.ts` — an external developer wiring up a
forwarder without a browser had to read that file (or the Go handlers) to
figure out the exact request shapes, including that `tenant_id` is a query
parameter on `POST /api/agents` while `name` is a JSON body field. This page
covers exactly the three endpoints between "I have no account" and "I have a
running `agentguard-forwarder`". It is not a full API reference for every
dashboard endpoint (events, metrics, anomalies, settings) — see
`dashboard/server/webapi.go` for those; they're all cookie-authenticated the
same way `POST /api/agents` is below.

**Shortcut:** `agentctl cloud signup` + `agentctl cloud agents create
--register` do all three calls below for you — see the end of this page. The
raw contract is documented here for anyone integrating without the CLI (a
script, a different language, CI).

## 1. Sign up — `POST /api/signup`

Creates a user and a new tenant (company/organization) in one call, and logs
the new user in. No `tenant_id` is needed here — one is created for you and
returned in the response.

- **Body:** JSON, all three fields required.
- **Auth:** none required to call it; sets a session cookie (`ag_session`)
  in the response, which every following `/api/...` call must send back.
- **Password:** minimum 8 characters.

```bash
curl -sS -c cookies.txt -X POST http://127.0.0.1:8090/api/signup \
  -H 'Content-Type: application/json' \
  -d '{"company_name": "Acme", "email": "you@acme.example", "password": "at-least-8-chars"}'
```

Response (`201 Created`):

```json
{ "user_id": "user_...", "tenant_id": "tenant_..." }
```

`-c cookies.txt` saves the `Set-Cookie` response header so the next call can
replay it with `-b cookies.txt`.

## 2. Create an agent — `POST /api/agents`

Registers a new agent under a tenant and mints a one-time registration
token for it. **`tenant_id` is a query parameter, not a body field** — the
one thing this endpoint's shape doesn't look like at first glance, and the
exact thing an external developer had to reverse-engineer.

- **Body:** JSON, `{"name": "..."}` only.
- **Query param:** `tenant_id` (required — this is how every tenant-scoped
  `GET`/`PUT`/`POST /api/...` endpoint takes its tenant, not just this one).
- **Auth:** the session cookie from step 1; the signed-in user must be an
  `admin` in that tenant (true automatically for the tenant `/api/signup`
  just created).

```bash
curl -sS -b cookies.txt -X POST 'http://127.0.0.1:8090/api/agents?tenant_id=tenant_...' \
  -H 'Content-Type: application/json' \
  -d '{"name": "my-coding-agent"}'
```

Response (`201 Created`):

```json
{ "agent_id": "agent_...", "registration_token": "..." }
```

The `registration_token` is single-use and expires the first time it's
redeemed (step 3) — it is not the credential the forwarder uses long-term.

## 3. Redeem the token — `POST /v1/agents/register`

This is the call `agentguard-forwarder -register-token=<token>` makes for
you; you don't need to call it directly unless you're building a different
client. Note the different base path (`/v1/...`, not `/api/...`) — this
endpoint belongs to the agent-facing Control API
(`dashboard/server/controlapi.go`), not the browser-facing one, and takes no
session cookie at all (the token itself is the credential, and it's
tenant-scoped implicitly).

- **Body:** JSON, `{"registration_token": "..."}`.
- **Auth:** none — the token is the credential, redeemable exactly once.

```bash
curl -sS -X POST http://127.0.0.1:8090/v1/agents/register \
  -H 'Content-Type: application/json' \
  -d '{"registration_token": "..."}'
```

Response (`200 OK`):

```json
{ "agent_id": "agent_...", "api_key": "..." }
```

The `api_key` is what a running `agentguard-forwarder` uses on every later
call (`Authorization: Bearer <api_key>`) — this is the credential worth
protecting; the registration token from step 2 is not reusable once this
succeeds.

## Doing all three at once

```bash
agentctl cloud signup --company Acme --email you@acme.example --password at-least-8-chars
agentctl cloud agents create --register my-coding-agent
```

The first command does step 1 and saves the session (default
`~/.agentguard/cloud-session.json`, override with `--state` or
`AGENTGUARD_CLOUD_SESSION`). The second does step 2 under the tenant that
signup created (override with `--tenant`) and, with `--register`, runs
`agentguard-forwarder -register-token=<token> -once` for you — step 3 — so
the agent shows up connected in the dashboard without touching a browser or
constructing a single request by hand. Run `agentguard-forwarder` again
without `-once` afterward for the real long-running sync loop.
