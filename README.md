# SentriMeshAstra

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
| 6 | Response | `backend/app/agents/response.py` | Proposes actions, executes tier-1 automatically, requests approval otherwise |
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
- **Dry-run execution by default**: nothing in this codebase reaches a
  real firewall, IdP, or EDR yet (see below). Every execution is logged
  and its intended effect is recorded, but nothing outside
  SentriMeshAstra's own database changes until you wire a real connector.
- **Multi-tenant isolation**: every table is scoped by `tenant_id`, and
  every route checks the caller's role/tenant before returning data. A
  security holder cannot see another company's tenant, even by ID.

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
uvicorn app.main:app --reload

# separately:
cd frontend
npm install
npm run dev
```

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

### Tests

```bash
cd backend && source .venv/bin/activate && python -m pytest tests/ -v
```

13 unit tests cover the policy engine's tier decisions (destructive
actions always human-only regardless of severity, tier escalation at
critical severity, etc.) and the detection/threat-intel pure logic.

## Scope and limits — read this before selling it

This MVP proves the architecture works end-to-end. It is not yet the
platform described in the full project plan. Specifically, **not
implemented**:

- **Real response execution.** `backend/app/connectors/executor.py` ships
  only a `DryRunExecutor`. Wiring an actual firewall/EDR/IdP (AWS Security
  Groups, Azure AD, CrowdStrike, etc.) means writing one `ActionExecutor`
  subclass per integration and selecting it per tenant connector config —
  the interface is ready, the integrations aren't written.
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
- **Multi-instance correlation state.** Detection's failed-login counters
  live in the process's memory (falling back to a DB check so an incident
  isn't duplicated across a restart, but the sliding-window counters
  themselves are not shared). Running more than one backend replica needs
  those counters moved to Redis.
- **Threat intelligence feeds.** `backend/app/connectors/threat_feed.py`
  ships a tiny local demo blocklist. No AbuseIPDB/VirusTotal/etc.
  integration is wired up — the call site is isolated so adding one is a
  single-file change.
- **Deeper authorized pentesting.** The Exposure agent does passive,
  read-only checks (TLS, security headers) against the tenant's own
  verified domain only. Active/authorized penetration testing is a scoped,
  contract-gated feature for a later phase — this repo intentionally does
  not build anything that could be pointed at a third party.
- **Alembic migrations.** Tables are created with `create_all` at startup.
  Fine for an MVP; move to versioned Alembic migrations before production
  schema changes.
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
