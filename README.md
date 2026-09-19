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
| 5 | Exposure | `backend/app/agents/exposure.py` | Scans the tenant's own verified domain for missing hardening, plus real OSINT search and dependency vulnerability checks |
| 6 | Response | `backend/app/agents/response.py` | Proposes actions, executes tier-1 automatically, requests approval otherwise, supports rollback |
| 7 | Compliance & Reporting | `backend/app/agents/reporting.py` | Daily reports, email notifications |
| 8 | Guardian | `backend/app/agents/guardian.py` | Independently re-checks every proposed action's tier, watches connector health, is the kill switch's home |

All 8 talk only over `backend/app/bus.py` (Redis pub/sub), and **every
message is written to the audit log before it's dispatched** — that's
`backend/app/routers/activity.py` on the console, the Guardian's ledger.

## Real-time, not polling

The console pushes, it doesn't poll. `backend/app/routers/ws.py` opens a
WebSocket per active tenant (`GET /ws/tenants/{id}?token=<jwt>`) and
`backend/app/realtime.py` bridges it to the same Redis bus the agents
talk over — every incident, enrichment, classification, action, and
report shows up in the browser the instant an agent publishes it, with
no fixed refresh delay. The frontend (`frontend/src/lib/liveEvents.js`)
opens one connection per active tenant (shared across every open page via
`SessionProvider`, not one per page), reconnects automatically with
backoff if it drops, and a small "● live" indicator on Overview shows the
connection state. Verified live end-to-end: a Playwright browser session
left sitting on the Incidents page picked up a newly ingested attack with
zero reloads or clicks — see the test suite below for the automated
version of the same check.

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
- **Security headers on every response**: `app/security_headers.py`
  (X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
  Permissions-Policy). HSTS is deliberately left to whatever terminates
  real TLS in front of this (a reverse proxy/CDN) rather than set here,
  since forcing it on a plain-HTTP dev instance breaks the browser's
  ability to fall back to HTTP.
- **Insecure-default warnings**: the app logs a loud warning at startup
  if `JWT_SECRET` or `BOOTSTRAP_ADMIN_PASSWORD` are still their
  placeholder values, rather than silently letting a forgotten `.env`
  edit become a production credential.
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

### There is no demo or simulated data

A freshly onboarded company starts completely empty — no connector, no
events, no incidents — until you add a real connector under Settings and
it starts actually receiving data. There used to be a "Simulate demo
attack" button and an auto-created synthetic connector for trying the
pipeline without a real log source; both were removed on purpose, so
nothing in this console is ever fabricated. To see the pipeline run,
either wire up a real SIEM/log source (see "Connecting a real log
source" below) or, for local development only, push a real-shaped event
through the real ingest endpoint yourself with a connector token you
mint from Settings:

```bash
curl -X POST http://localhost:8000/api/tenants/<tenant_id>/ingest \
  -H "Authorization: Bearer <connector_token>" \
  -H "Content-Type: application/json" \
  -d '{"source": "test", "event_type": "login_failed", "data": {"src_ip": "203.0.113.7", "user": "root"}}'
```

That's real traffic through the real pipeline — Detection correlates it,
Threat Intelligence looks the IP up against a real source (AbuseIPDB, if
configured — see below), Orchestrator classifies it, Response proposes an
action. Nothing about that flow is different from what a real forwarder
triggers; it's just you sending one event by hand instead of Wazuh
sending thousands.

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

### Threat intelligence — real only, no fallback, multi-source

Set any subset of `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`
(AlienVault OTX), `GREYNOISE_API_KEY`, `SHODAN_API_KEY`, and
`ABUSECH_AUTH_KEY` (ThreatFox) and the Threat Intelligence agent queries
every one configured, in parallel, for real IP reputation
(`backend/app/connectors/threat_feed.py`). A source with no key
configured is simply skipped; a source whose call fails (timeout, bad
response, rate limit) degrades to "no data from this source," not a
failure of the whole lookup — the other configured sources still get a
say. The aggregate verdict is `malicious` if any source says so (a
confirmed ThreatFox malware-family match, or two-plus VirusTotal engines
agreeing, is never averaged away by a "clean" from a different source),
`suspicious` if any source flags it short of that bar, `clean` if every
reachable source came back clean (or GreyNoise identifies it as a known
business service via RIOT), and an honest `unknown` if nothing is
configured or every configured source's call failed. Shodan is
deliberately never the sole reason for a `malicious` verdict — it profiles
what's running on a host (open ports, known CVEs on exposed services),
which is real exposure context, not a reputation claim about the traffic
itself. Without any source configured, enrichment honestly reports
`unknown` — there is no local blocklist standing in as if it were real
data — and Response can only `notify` (auto, tier-1) for a brute-force
incident rather than propose a `block_ip` action, since nothing confirmed
the intent. Set real keys to get real confirmed-malicious classification
and the one-tap block proposal that comes with it.

### Dependency vulnerability scanning (OSV.dev + GitHub Advisory Database)

`POST /api/tenants/{tenant_id}/dependency-scan` takes a list of
`{ecosystem, name, version}` packages the tenant declares — e.g. lines
parsed from their own `requirements.txt`/`package.json` — and the
Exposure agent checks each against two real, free sources
(`backend/app/connectors/vuln_scanner.py`): OSV.dev (Google-run,
fully unauthenticated, aggregates GitHub Security Advisories plus every
major ecosystem's own advisory database) and the GitHub Advisory Database
itself (public REST API, no token required). The same CVE/GHSA surfaced
by both sources is deduplicated, not double-counted; a source that fails
is named as unreachable in the result rather than silently counted as "no
known vulnerabilities." Neither source needs an API key — this capability
works with zero configuration.

### Public-exposure OSINT search (SerpAPI)

Set `SERPAPI_API_KEY` and every domain exposure scan also runs one real
Google search (via SerpAPI), restricted to the tenant's own domain, for
the file types and directory-listing pattern that most commonly indicate
an accidental public exposure (`site:{domain} (filetype:env OR
filetype:sql OR filetype:log OR intitle:"index of")`) — the same
non-intrusive technique real attack-surface-management tools use, never
anything beyond a plain search of a domain the tenant already told us
they own. A real hit becomes a real exposure finding with the actual
indexed URL; without the key, this one step is simply skipped.

### Impossible-travel detection (real algorithm, not a heuristic guess)

`app/geo.py` implements the actual algorithm real identity-protection
tools use for this: haversine great-circle distance between two known
country locations, divided by the elapsed time between two sign-ins for
the same user, compared against a speed no legitimate traveler can
exceed (1000 km/h — faster than commercial aviation). A country comes
either directly from the event source (Azure AD sign-in logs supply
`location.countryOrRegion` natively — most accurate, zero extra calls)
or, if `IPINFO_API_KEY` is set, from a real `ipinfo.io` lookup of the
source IP. Without either, impossible-travel simply isn't evaluated for
that event — never a guessed location. A confirmed hit classifies as
HIGH severity on its own and the Orchestrator recommends
`force_password_reset` (tier-2, one-tap) — this is exactly the situation
where "notify and see" is the wrong call. Verified live: two real
Azure-AD-shaped sign-ins for the same user, US then Russia, ~2 seconds
apart, correctly produced a HIGH-severity incident with a genuinely
computed ~15 million km/h implied speed and the real haversine distance
behind it (`backend/tests/test_geo.py`,
`test_impossible_travel_detected_from_real_azure_ad_sign_ins` in
`test_api_integration.py`).

### Malware/rootkit detection (real Wazuh rule groups, not invented ones)

A Wazuh alert in its real `rootcheck`/`malware`/`virus` rule groups (or
whose `rule.description` plainly names a trojan/rootkit finding — some
malware integrations don't use a dedicated group) classifies as
`malware_detected`. This is direct, first-party evidence of compromise —
weighted the same as a confirmed-malicious IP from Threat Intelligence —
so it reaches MEDIUM severity on its own (CRITICAL if it stacks with
another signal, e.g. new admin activity), and the Orchestrator recommends
`quarantine_endpoint` (tier-2, one-tap, reversible). There's no real
EDR/agent integration in this platform to actually isolate the host, so
that action dry-runs like every action type besides `block_ip` — but the
classification, severity, and incident description (Wazuh's own
`rule.description`, verbatim) are all real, not placeholders. Verified
live: a real Wazuh `rootcheck` alert through the full ingest pipeline
correctly opened a MEDIUM-severity incident with a pending
`quarantine_endpoint` approval (`backend/tests/test_log_formats.py`,
`test_wazuh_malware_alert_opens_incident_with_real_rule_description` in
`test_api_integration.py`).

### Email notifications — real SMTP, verified end-to-end

Set `SMTP_HOST` (plus `SMTP_PORT`/`SMTP_USERNAME`/`SMTP_PASSWORD`/
`SMTP_FROM`/`NOTIFY_TO_EMAIL`) and tier-2/tier-3 approval requests really
send over SMTP with STARTTLS (`app/notifications/email.py`, via
`aiosmtplib`) — not a fire-and-forget call assumed to work. Without
`SMTP_HOST` configured, or if a send genuinely fails (relay unreachable,
auth rejected), it's logged instead — the platform never silently drops a
notification, and never crashes an agent's task just because email isn't
set up. `backend/tests/test_email_smtp.py` proves the real send path, not
just the log fallback: it runs an actual local SMTP server (`aiosmtpd`)
with a real, freshly-generated self-signed TLS certificate, sends through
the app's real `send_email()`, and asserts the message that server
*actually received* — headers, recipient override, and body — matches
what was sent, alongside real-failure-path tests (unreachable relay,
unconfigured SMTP) that confirm both fail closed to the log fallback
rather than raising.

### Connecting a real log source (Wazuh, etc.)

Settings → "Add connector & issue token" mints a per-connector secret
(shown exactly once) and stores only its hash. Point the forwarder at
`POST /api/tenants/{tenant_id}/ingest` with `Authorization: Bearer
<token>` — no human session token involved. A leaked token is remediated
by rotating it (invalidates the old one immediately) rather than needing
to delete and recreate the connector. Ingest accepts only a connector
token — deliberately no human-JWT fallback, so every event in the
pipeline traces back to a data source the tenant registered and can
revoke, never to someone hand-typing a payload into their own session.

The connector type you pick at creation decides how its events get
parsed (`backend/app/connectors/log_formats.py`) — not a field inside
the event payload itself, so a connector can't claim a trust level it
wasn't registered for:

- **`wazuh`** — real Wazuh alert JSON (`rule.*`, `data.*`, `agent.*`).
  When the alert carries `rule.mitre.id`/`technique` (Wazuh's ruleset
  populates this for many rules), that vendor classification is used
  directly for the incident's MITRE ATT&CK techniques — more accurate
  than any heuristic we could infer from field names, because it's
  Wazuh's own real analysis of that exact alert. Recognizes
  authentication success/failure, privilege escalation (`sudo`/
  `privilege_escalation` groups), and malware/rootkit findings
  (`rootcheck`/`malware`/`virus` groups — see below).
- **`cloudtrail`** — real AWS CloudTrail event records (`eventName`,
  `userIdentity`, `errorCode`, `sourceIPAddress`, ...). Recognizes
  `ConsoleLogin` (success/failure) and privilege-escalation-shaped API
  calls (`AttachUserPolicy`, `CreateAccessKey`, `AddUserToGroup`, ...).
- **`azure_ad`** — real Azure AD sign-in log schema (`ipAddress`,
  `userPrincipalName`, `status.errorCode`, `location.countryOrRegion`,
  ...). `errorCode == 0` is success; Microsoft's documented nonzero
  codes (e.g. 50126 = invalid credentials) are a failure.
- **anything else** — best-effort generic guessing on common field names
  (`src_ip`/`source_ip`, `user`/`username`, `outcome`). No fixed vendor
  schema to parse against, so no vendor-specific accuracy claimed.

Try it directly:

```bash
curl -X POST http://localhost:8000/api/tenants/<tenant_id>/ingest \
  -H "Authorization: Bearer <token for a wazuh-typed connector>" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "wazuh",
    "data": {
      "rule": {"id": "5710", "level": 10, "description": "Multiple authentication failures.",
               "groups": ["authentication_failed"],
               "mitre": {"id": ["T1110"], "technique": ["Brute Force"]}},
      "data": {"srcip": "203.0.113.7", "srcuser": "root"}
    }
  }'
```

### Tests

```bash
cd backend && source .venv/bin/activate && python -m pytest tests/ -v
```

103 tests, three kinds:

- **Unit tests** (policy engine tier decisions, detection/threat-intel
  pure logic, the real per-vendor log parsers against sample payloads
  shaped exactly like Wazuh/CloudTrail/Azure AD's own documented
  schemas — `tests/test_log_formats.py` — the AbuseIPDB no-fallback
  behavior — including a regression test locking in that RFC 5737
  test-net ranges must still reach AbuseIPDB, since Python's
  `ipaddress.is_private` would otherwise silently swallow them — Redis-
  backed sliding-window counters, including
  a same-counter-from-two-connections test standing in for two backend
  replicas, login lockout logic, and, when run as root with `iptables`
  available, a real block-then-rollback round trip against the host's
  firewall). A handful skip automatically if Redis isn't reachable,
  rather than failing for an environment gap.
- **API integration tests** (`tests/test_api_integration.py`) drive the
  real FastAPI app — real Alembic migrations, a real Postgres database, a
  real Redis-backed agent bus with all 8 agents actually running — via
  `httpx.AsyncClient`, pushing events through the real connector-token
  ingest endpoint (never a demo/simulate route — there isn't one). The
  one thing mocked is the third-party AbuseIPDB HTTP call itself, at the
  test boundary, so the suite doesn't need network access or a committed
  API key; everything downstream of that mock (severity scoring, the
  block_ip proposal, the approval it creates) is the app's real,
  unmocked logic. They cover tenant onboarding and isolation, the
  full attack-to-pending-approval pipeline, approve/reject/rollback,
  kill-switch enforcement (including the security-holder-can't-disengage
  rule), report generation, per-tenant activity scoping, and admin-only
  platform audit access. They run against a dedicated `sentrimesh_test`
  database (dropped and recreated fresh each test session) and a separate
  Redis logical DB — never your dev data.
- **WebSocket tests** (`tests/test_realtime_ws.py`) run a real bound
  uvicorn server and connect with a real `websockets` client — not
  Starlette's simulated-ASGI TestClient — because a genuine handshake and
  a genuine socket are the actual thing being tested. Cover: real events
  pushed end-to-end within the dashboard channel set, and rejection for
  no token, an invalid token, and a security holder connecting to a
  tenant that isn't theirs.

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
- **SIEM connectors beyond Wazuh/CloudTrail/Azure AD.** Those three have
  real, schema-accurate parsers (`backend/app/connectors/log_formats.py`)
  — matching each vendor's own documented JSON shape, and for Wazuh,
  using the alert's own embedded MITRE ATT&CK classification
  (`rule.mitre.id`/`technique`) directly rather than guessing one. A
  connector registered as any other type (Splunk, a custom tool, etc.)
  falls back to best-effort generic field guessing — honestly labeled as
  such in Settings, not silently treated as if it had a dedicated parser.
  Splunk doesn't get one here because it has no single canonical event
  schema to parse against (it indexes whatever you send it); adding a
  parser for one more fixed-schema vendor (GuardDuty, Okta System Log,
  etc.) is the same pattern as the three that exist — see
  `app/connectors/log_formats.py`.
- **Per-tenant hard isolation.** Tenancy today is one shared database with
  `tenant_id` scoping, enforced at the query layer and covered by tests
  (a security holder gets a 403 touching another tenant's data, even by
  ID). Two further layers are deliberately not done here: (1) Postgres
  row-level security as defense-in-depth against a future query bug —
  the correct design needs two DB roles, a restricted one for
  human-request sessions and a privileged one for the agent fleet (which
  runs outside any per-request tenant context entirely, reacting to bus
  events), and wiring that role split in without silently breaking agent
  writes is a real, careful piece of work, not a quick patch; (2)
  separate databases/encryption keys per customer, which is genuinely an
  infrastructure project.
- **Threat intelligence feeds beyond AbuseIPDB.** VirusTotal, file-hash and
  CVE lookups aren't wired up — the call site is isolated so adding one is
  a single-file change, same pattern as the AbuseIPDB integration.
- **WebSocket fan-out at scale.** Each open dashboard tab holds its own
  Redis pub/sub subscription (`app/realtime.py`) — simple and correct at
  the scale of one open tab per person watching a company's console.
  Hundreds of simultaneously open tabs would mean hundreds of Redis
  subscriptions doing the same tenant-filtering work independently; the
  fix at that scale is a small fan-out layer (one subscription, broadcast
  to many WebSocket connections), not a redesign of the push mechanism
  itself.
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
