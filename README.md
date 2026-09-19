# SentriMeshAstra

[![CI](https://github.com/veerasivasatyavaraprasad-netizen/-SentriMeshAstra/actions/workflows/ci.yml/badge.svg)](https://github.com/veerasivasatyavaraprasad-netizen/-SentriMeshAstra/actions/workflows/ci.yml)

An AI security team platform: a small fleet of agents that monitors a
company's own connected systems (logs, cloud, endpoints), investigates,
proposes and — within limits it cannot cross on its own — executes a
response, and reports daily. One person (the company's designated
**security holder**) approves the decisions that matter; the platform
owner (**admin**) onboards companies and holds the disengage-only side of
the kill switch.

## What this is, precisely

This is a working MVP of the architecture, not a finished commercial
product. It implements the full pipeline end-to-end — detection, threat
intel enrichment, severity classification, tiered autonomy, human
approval, dry-run response execution, daily reporting, and a full audit
trail — against real infrastructure you can run locally in minutes. What
it does **not** do, on purpose, is described in [Scope and limits](#scope-and-limits)
below. Read that section before pitching this to a customer.

## The 8 agents

| # | Agent | File | Job |
|---|-------|------|-----|
| 1 | Orchestrator | `backend/app/agents/orchestrator.py` | Classifies severity, decides the recommended action |
| 2 | Integration | `backend/app/agents/integration.py` | Normalizes incoming events, tracks connector health |
| 3 | Detection & Triage | `backend/app/agents/detection.py` | Correlates events, dedups ongoing campaigns, opens incidents, maps MITRE ATT&CK |
| 4 | Threat Intelligence | `backend/app/agents/threat_intel.py` | Looks up IP/indicator reputation, enriches incidents |
| 5 | Exposure | `backend/app/agents/exposure.py` | Scans the tenant's own verified domain for missing hardening |
| 6 | Response | `backend/app/agents/response.py` | Proposes actions, executes tier-1 automatically, requests approval otherwise, supports rollback |
| 7 | Compliance & Reporting | `backend/app/agents/reporting.py` | Daily reports, email notifications |
| 8 | Guardian | `backend/app/agents/guardian.py` | Independently re-checks every proposed action's tier, watches connector health, is the kill switch's home |

All 8 talk only over `backend/app/bus.py` (Redis pub/sub), and **every
message is written to the audit log before it's dispatched** — that's
`backend/app/routers/activity.py` on the console, the Guardian's ledger.

## The safety model

- **Autonomy tiers** (`backend/app/policy/engine.py`): every proposed
  action is classified tier-1 (auto-run, read-only/low-risk), tier-2
  (one-tap approval, reversible), or tier-3 (human-only — destructive or
  irreversible, no exceptions, regardless of severity).
- **Approval**: only a human (admin or the company's security holder) can
  resolve a tier-2/3 approval. No agent, including the Orchestrator, can
  skip this.
- **Kill switch**: either the admin or the tenant's own security holder can
  *engage* it (stop all automated/approved execution immediately); only
  the admin can *disengage* it. Checked by the Response agent immediately
  before every execution, even for an already-approved action.
- **Dry-run execution by default**: `block_ip` can really execute — see
  [Real response execution](#real-response-execution-block_ip) below — but
  it's off unless you explicitly opt in, and every other action type stays
  a logged, dry-run simulation until its own executor is written. Nothing
  outside what you opt into changes until you wire a real connector.
- **Rollback**: every reversible executed action can be rolled back from
  the Approvals page (or `POST /api/tenants/{id}/actions/{id}/rollback`).
  Against the dry-run executor this simulates the rollback; against
  `IPTablesExecutor` it really removes the block.
- **Multi-tenant isolation**: every table is scoped by `tenant_id`, and
  every route checks the caller's role/tenant before returning data. A
  security holder cannot see another company's tenant, even by ID.
- **Login brute-force lockout**: `app/ratelimit.py` counts failed attempts
  per email and per source IP in Redis (shared across replicas); either
  one crossing its threshold (defaults: 8/email, 30/IP, 5-minute window)
  locks out further attempts, including a correct password, until the
  window rolls off. Every failure and lockout is written to the audit
  log; the admin sees them under Settings → Platform security log.

## Two logins

- **Admin** — you, the platform owner. Onboards companies, creates their
  security-holder login, can disengage any kill switch, can see every
  tenant.
- **Security holder** — the one person per company who approves tier-2/3
  actions and can engage (but not disengage) their own kill switch. Scoped
  strictly to their own tenant.

## Running it

### Docker Compose (recommended)

```bash
cp .env.example .env   # edit ADMIN password, and optionally ANTHROPIC_API_KEY / SMTP
docker compose up --build
```

- Backend: http://localhost:8000 (docs at `/docs`)
- Frontend: http://localhost:5173
- Log in with the `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` from `.env`.

### Local dev (no Docker)

```bash
# Postgres + Redis running locally, then:
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql+asyncpg://sentrimesh:sentrimesh@localhost:5432/sentrimesh
export REDIS_URL=redis://localhost:6379/0
uvicorn app.main:app --reload    # runs `alembic upgrade head` automatically on startup

# separately:
cd frontend
npm install
npm run dev
```

Schema changes go through Alembic (`backend/alembic/versions/`), not
`create_all`. After changing a model in `app/models.py`, generate a new
migration with `alembic revision --autogenerate -m "..."` from `backend/`
(with `DATABASE_URL` set) and commit the generated file — the app applies
it automatically on its next startup.

### Try the full pipeline without any real log source

1. Log in as admin, create a company (Settings → "onboard a new company").
   A synthetic demo connector is attached automatically.
2. Go to Overview and click **Simulate demo attack**. This fires a
   realistic brute-force scenario (6 failed logins + 1 success from a
   demo "malicious" IP) through the real pipeline.
3. Watch Incidents (an incident opens, gets enriched, gets classified
   high-severity), then Approvals (a one-tap `block_ip` action is
   waiting), then Agent Activity (every message any agent sent, in order).
4. Approve it — the dry-run executor logs what it *would* do. Generate a
   report from the Reports page to see the daily-report narrative.
5. Try Overview → **Engage kill switch**, then simulate another attack and
   approve its action: execution is blocked and the audit log records why.

### Real response execution (`block_ip`)

By default every action executes as a dry-run — logged, never real. Set
`ENABLE_REAL_RESPONSE_EXECUTION=true` and `block_ip` really firewalls the
**host this backend runs on** via `iptables` (see
`backend/app/connectors/executor.py::IPTablesExecutor`), with a genuine,
tested rollback. This is a real integration, not a mock — but it firewalls
whatever machine is running the backend, so only enable it where that
machine *is* your enforcement point (an edge/gateway host), never a shared
app server. Every other action type still dry-runs regardless of this
flag, since no other executor exists yet.

### Real threat intelligence

Set `ABUSEIPDB_API_KEY` and the Threat Intelligence agent looks up real IP
reputation via the AbuseIPDB API instead of the local demo blocklist. Any
failure (timeout, bad response, no key) falls back to the local list
automatically — a flaky third party never breaks the pipeline.

### Tests

```bash
cd backend && source .venv/bin/activate && python -m pytest tests/ -v
```

38 tests, two kinds:

- **Unit tests** (policy engine tier decisions, detection/threat-intel
  pure logic, the AbuseIPDB fallback path, Redis-backed sliding-window
  counters — including a same-counter-from-two-connections test standing
  in for two backend replicas — login lockout logic, and, when run as
  root with `iptables` available, a real block-then-rollback round trip
  against the host's firewall). A handful skip automatically if Redis
  isn't reachable, rather than failing for an environment gap.
- **API integration tests** (`tests/test_api_integration.py`) drive the
  real FastAPI app — real Alembic migrations, a real Postgres database, a
  real Redis-backed agent bus with all 8 agents actually running — via
  `httpx.AsyncClient`. They cover tenant onboarding and isolation, the
  full attack-to-pending-approval pipeline, approve/reject/rollback,
  kill-switch enforcement (including the security-holder-can't-disengage
  rule), report generation, per-tenant activity scoping, and admin-only
  platform audit access. They run against a dedicated `sentrimesh_test`
  database (dropped and recreated fresh each test session) and a separate
  Redis logical DB — never your dev data.

## Scope and limits — read this before selling it

This MVP proves the architecture works end-to-end. It is not yet the
platform described in the full project plan. Specifically, **not
implemented**:

- **Response execution beyond `block_ip`.** `IPTablesExecutor` is a real,
  tested integration for one action against one kind of target (this
  host's own firewall). Every other action type (`disable_account`,
  `quarantine_endpoint`, etc.) and any customer cloud/IdP/EDR integration
  (AWS Security Groups, Azure AD, CrowdStrike, etc.) still needs its own
  `ActionExecutor` subclass — the interface and the rollback contract are
  proven, the rest of the integrations aren't written.
- **Real SIEM connectors.** Only a generic webhook (`POST
  /api/tenants/{id}/ingest`) and a synthetic demo feed exist. A real Wazuh
  (or Splunk, CloudTrail, Azure AD sign-in log, etc.) forwarder needs its
  own field-mapping in `backend/app/agents/integration.py::normalize()`.
- **Per-tenant hard isolation.** Tenancy today is one shared database with
  `tenant_id` scoping — logical isolation, enforced at the query layer.
  Separate databases/encryption keys per customer (the project plan's
  hardening goal) is a real infrastructure project, not done here.
- **Machine-to-machine connector auth.** The ingest endpoint currently
  authenticates with the console's own JWT. A real SIEM forwarder needs a
  per-connector secret token instead.
- **Threat intelligence feeds beyond AbuseIPDB.** VirusTotal, file-hash and
  CVE lookups aren't wired up — the call site is isolated so adding one is
  a single-file change, same pattern as the AbuseIPDB integration.
- **Deeper authorized pentesting.** The Exposure agent does passive,
  read-only checks (TLS, security headers) against the tenant's own
  verified domain only. Active/authorized penetration testing is a scoped,
  contract-gated feature for a later phase — this repo intentionally does
  not build anything that could be pointed at a third party.
- **Secrets vault, SOC 2/ISO 27001, external pentest, bug bounty.** All
  named in the original plan's hardening section as pre-launch
  requirements for handling many customers' data — none of that is a
  software change this repo can contain; they're organizational/process
  work for before a real launch.

None of the above blocks using this as the foundation the project plan's
phased roadmap (Foundation → Safety → Capability → Pilots → Commercial
launch → Expansion) describes — it's meant to be exactly that foundation.

## A note on what this platform will and won't do

This system only ever acts on infrastructure a customer has explicitly
connected (their own logs, cloud accounts, endpoints) with credentials
they provided. It does not — and this repo will not be extended to —
target, scan, or act on systems a customer doesn't own or hasn't
authorized. "Exposure" scanning is limited to a tenant's own verified
domain and is passive. Anything closer to active penetration testing
belongs in a separately scoped, contractually authorized engagement, not
an always-on agent.
