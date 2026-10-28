# 04 — System design and contracts

This is the source of truth. `shared/schemas.py` implements it in code. If they
disagree, this doc wins and Jerush fixes the code.

## 1. Request flow

```
            ┌───────────── runner (corpus replay) / real browser
            ▼
        gateway :8000 ── verdict ──┬── SAFE   ──► bank :8001 ──► response
            │                      ├── DENY   ──► 403 JSON
            │                      └── DIVERT ──► honeypot :8002 ──► response to attacker
            │                                  └► sandbox :8003 /replay ──► bank-sandbox :8001
            │
            └── every service ──► Redis stream "events" ──► analyst :8004
                                                              │  ├─ persists to Postgres
                                                              │  ├─ DIVERT → defense LLM → rule
                                                              │  └─ rule → Redis "rules:active" + pub "rules:updated"
                                                              ▼
                                                   dashboard :3000 (WS /ws/live)
```

## 2. Services

| Service | Port | Owner | Image / stack | Networks | Host port in dev |
|---|---|---|---|---|---|
| gateway | 8000 | Abhinav | Python 3.11, FastAPI, httpx | edge, internal | 8000 |
| sandbox | 8003 | Abhinav | Python 3.11, FastAPI | internal | 127.0.0.1:8003 |
| bank | 8001 | Akchhat | Python 3.11, FastAPI, SQLite | internal | 127.0.0.1:8001 |
| bank-sandbox | 8001 | Akchhat (same image as bank, fresh DB each start) | — | internal | none |
| honeypot | 8002 | Akchhat | Python 3.11, FastAPI | internal | 127.0.0.1:8002 |
| dashboard | 3000 | Akchhat | React + Vite + TS, served by nginx | edge | 3000 |
| analyst | 8004 | Jerush | Python 3.11, FastAPI, asyncpg | edge, internal | 8004 |
| runner | 8005 | Jerush | Python 3.11, FastAPI | edge | 8005 |
| mock-llm | 8009 | Jerush | Python 3.11, FastAPI | edge | none |
| redis | 6379 | Jerush | redis:7-alpine | internal | 127.0.0.1:6379 |
| postgres | 5432 | Jerush | postgres:16-alpine | internal | 127.0.0.1:5432 |

- `docker-compose.yml` publishes only gateway and dashboard. `docker-compose.override.yml`
  (auto-loaded in dev) adds the 127.0.0.1 ports above. It also attaches those services to `edge`,
  because Docker can't publish ports for a container that is only on an `internal: true`
  network. That's dev-only convenience. The homelab runs
  `docker compose -f docker-compose.yml up` so the override is skipped.
- The `internal` network has `internal: true`, so it has no internet access.
- The dashboard's nginx proxies `/api/*` and `/ws/*` to `analyst:8004`, so the browser
  only ever talks to port 3000. In `npm run dev`, Vite proxies the same paths to `localhost:8004`.
- Every Dockerfile uses build context `.` (repo root) and does `COPY shared /app/shared`.

## 3. Environment variables (`.env.example`)

```
LLM_MODE=mock                 # mock | kaggle | local
DEFENSE_LLM_URL=http://mock-llm:8009
DEFENSE_LLM_KEY=
LOCAL_LLM_URL=http://host.docker.internal:8080
DEMO_OFFLINE=0                # 1 = analyst uses canned rules, no network
DIVERT_THRESHOLD=0.7
REDIS_URL=redis://redis:6379/0
DATABASE_URL=postgresql://sphere:sphere@postgres:5432/sphere
GATEWAY_URL=http://gateway:8000
BANK_URL=http://bank:8001
BANK_SANDBOX_URL=http://bank-sandbox:8001
HONEYPOT_URL=http://honeypot:8002
SANDBOX_URL=http://sandbox:8003
ANALYST_URL=http://analyst:8004
RUNNER_URL=http://runner:8005
RUNNER_ALLOWED_TARGETS=http://gateway:8000
```

Need a new variable? Ask Jerush to add it here and in `.env.example`.

## 4. Shared code (`shared/`, Jerush only)

| File | Contents |
|---|---|
| `shared/schemas.py` | Pydantic v2 models below |
| `shared/owasp.py` | `OWASP_2025: dict[str, str]` mapping `"A01"` to its name |
| `shared/events.py` | `async def emit(redis, event: Event)` writes to the stream |
| `shared/config.py` | `Settings` (pydantic-settings) reading the env vars above |

## 5. Event schema (Contract 1)

Every service emits this to the Redis stream `events` (`XADD events * data <json>`).
Only `analyst` reads the stream and writes Postgres.

```python
OwaspId = Literal["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"]

class RequestInfo(BaseModel):
    method: str
    path: str
    query: str = ""
    ip: str
    user_agent: str = ""
    body_excerpt: str = ""        # max 500 chars, truncated
    body_sha256: str = ""

class Event(BaseModel):
    id: UUID                       # new per event
    ts: datetime                   # UTC
    source: Literal["gateway","sandbox","honeypot","analyst","runner"]
    correlation_id: str            # gateway's X-Request-Id; links all events for one request
    verdict: Literal["SAFE","DIVERT","DENY"] | None = None
    owasp: OwaspId | None = None
    rule_id: str | None = None
    score: float = 0.0             # anomaly score 0..1
    request: RequestInfo
    scenario_step: str | None = None   # set by runner via X-Scenario-Step header
    details: dict = {}             # free-form, e.g. sandbox status code, honeypot route
```

## 6. Rule schema (Contract 2)

Stored in Postgres `rules` and mirrored to Redis hash `rules:active` (field = id, value = JSON).
`analyst` is the only writer. After writing, it publishes the id on channel `rules:updated`.
Rule packs are loaded by `analyst` at start from `gateway/rules/packs/*.yaml`, so even pack rules flow
through the same path.

- `rules:active` holds **enabled rules only**. Disabling a rule removes it from the hash.
- The `rules:updated` message is a rule id, or `*` after a full reload (analyst start). Either way the
  gateway should just reload the whole hash.

```python
class Rule(BaseModel):
    id: str                        # pack: "sqli-001"; learned: "L-" + 8 hex
    owasp: OwaspId
    match_type: Literal["regex","rate","path","header"]
    target: Literal["path","query","body","header","any"] = "any"   # for regex/header
    pattern: str = ""              # regex or path glob
    params: dict = {}              # rate: {"key":"ip"|"account","limit":10,"window_s":60}
    action: Literal["DENY","DIVERT"]
    source: Literal["pack","learned"]
    description: str
    created_at: datetime
    enabled: bool = True
    hits: int = 0
```

Rule pack YAML (`gateway/rules/packs/<name>.yaml`, Abhinav):

```yaml
- id: sqli-001
  owasp: A05
  match_type: regex
  target: query
  pattern: "<regex here>"
  action: DENY
  description: "Classic tautology in a query parameter"
```

## 7. Gateway decision order (Abhinav)

1. Path rules → 2. Rate rules (Redis counters `rate:<rule_id>:<key>`, TTL = window) →
3. Regex/header rules (pack first, then learned) → 4. Anomaly score.
The first DENY wins. Otherwise the first DIVERT wins. Otherwise score ≥ `DIVERT_THRESHOLD` means DIVERT, else SAFE.

A01 account ownership is checked **after** the bank answers (GET only, so no side effects): the gateway
remembers `token → customer` from successful logins, and if `GET /api/accounts/{id}` returns an account whose
`customer_id` isn't the caller's, it replaces the response with a DENY (`rule_id: "access-account-owner"`, A01).

Every response carries the headers `X-Request-Id` and `X-Verdict`. A DENY returns:

```json
{"verdict":"DENY","rule_id":"sqli-001","owasp":"A05","request_id":"..."}
```

The gateway subscribes to `rules:updated` and reloads `rules:active` (target: under 1 s).

## 8. HTTP contracts (Contract 3)

All services: `GET /health` → `{"status":"ok"}`.

### sandbox (Abhinav)
- `POST /replay` body `{correlation_id, method, path, query, headers, body_b64}` → `202`.
  It replays against `BANK_SANDBOX_URL`, then emits an event with `source="sandbox"`,
  `details={"status":int,"error":str|null,"latency_ms":int,"stack_trace_leaked":bool}`.

### bank (Akchhat) — routes and the intentional weakness each one has

| Route | Weakness (for the demo) | OWASP |
|---|---|---|
| `POST /api/login` | No lockout; plain-HTTP accepted; weak hash | A07, A04 |
| `GET /api/accounts/{id}` | No ownership check | A01 |
| `POST /api/transfer` | No per-minute or amount limits | A06 |
| `GET /api/transactions/search?q=` | Unsafe query building | A05 |
| `POST /api/transactions/{id}/memo` | Memo written to log unsanitized | A05 |
| `POST /api/support/chat` | Bot with an "internal note" in its prompt (mock bot, no real LLM) | A05 |
| `GET /api/statements/fetch?url=` | Fetches a URL server-side (only reaches the internal network) | A01 |
| `GET /admin`, `GET /debug` | No auth, debug info | A02 |
| Session token | Not signature-checked | A08 |
| Any route on bad input | Stack trace in the 500 response | A10 |

Request bodies (JSON). The corpus, honeypot and runner must send exactly these:

| Route | Body |
|---|---|
| `POST /api/login` | `{"email": str, "password": str}`. Seed logins are `customer<N>@example.test` / `password123` |
| `POST /api/transfer` | `{"from_account_id": int, "to_account_id": int, "amount": float}` |
| `POST /api/transactions/{id}/memo` | `{"memo": str}` |
| `POST /api/support/chat` | `{"message": str}` |

### honeypot (Akchhat)
- Same routes and response shapes as the bank, with fake data and no real effects.
- Each request emits an event with `source="honeypot"`, `details={"route":str,"action":str}`.

### analyst (Jerush)
- `POST /analyze` body `Event` → `{"rule": Rule | null, "reason": str}`
- `GET /api/events?since=<iso>&limit=100` → `Event[]` (newest first)
- `GET /api/rules` → `Rule[]`; `PATCH /api/rules/{id}` body `{"enabled": bool}`
- `GET /api/stats` →
  ```json
  {"totals":{"SAFE":0,"DIVERT":0,"DENY":0},
   "owasp":{"A01":{"DIVERT":0,"DENY":0}, "...": {}},
   "learned_rules":0}
  ```
- `GET /api/timers` → `[{"rule_id","owasp","first_seen","rule_created","first_blocked","seconds"}]`
- `POST /api/scenario/run` body `{"scenario":"full"}` → `{"run_id": str}` (forwards to runner)
- `WS /ws/live` pushes `{"type":"event"|"rule"|"stats","data":{...}}`
- Honeypot console (sentinel-trap replica, served by the dashboard at `/honeypot/`): `GET /api/hp/{stats,sessions,events,
  data-contrast,bans,rules,analyses,final-report,llm/status,llm/config}`, `WS /ws/hp`; write actions (`POST /api/hp/{reset,
  mark-safe,ban-all,ban-account,llm/config,llm/test}`, `POST /api/hp/rules/{id}/toggle`) need header `X-Admin-Token: $ADMIN_TOKEN`.
  **Bans are display-only**: Redis keys `hp:ban:<ip>` with a 10-minute TTL, never read by the gateway. Reset clears events,
  learned rules, bans and rate counters (the LLM settings are kept).
- Learning loop (`analyst/app/learner.py`): every gateway DIVERT → wait ≤ 2 s for honeypot/sandbox events → LLM (or canned
  when `DEMO_OFFLINE=1` / AI off) → validate (also: must match the triggering request) → `L-xxxxxxxx` DENY rule → publish.
  The LLM base URL/key can be changed at runtime from the console's settings (a trycloudflare URL changes every Kaggle run).

### runner (Jerush)
- `POST /run` body `{"scenario": str}` → `{"run_id"}`; `GET /runs/{id}` → progress.
- Reads `tests/corpus/scenarios/<scenario>.yaml` and sends the referenced corpus items
  to the gateway with header `X-Scenario-Step`. It refuses any target not in `RUNNER_ALLOWED_TARGETS`.

### mock-llm (Jerush)
- `POST /v1/chat/completions` (OpenAI format). It returns a canned `RuleProposal` JSON in
  `choices[0].message.content`, picked by the OWASP id found in the prompt.

## 9. Defense LLM contract

- OpenAI-compatible `POST {DEFENSE_LLM_URL}/v1/chat/completions` with header
  `Authorization: Bearer {DEFENSE_LLM_KEY}`.
- The model must reply with one JSON object:
  `RuleProposal = {owasp, match_type, target, pattern, params, action, description}`.
- The analyst rejects a proposal if:
  - it isn't valid JSON or fails the schema
  - the regex doesn't compile, or the pattern is shorter than 3 or longer than 300 characters
  - it would match more than 1% of the last 500 SAFE events
- On rejection the analyst retries once, then falls back to a canned rule.
- Only these fields are sent to the LLM: method, path, query, body excerpt (≤ 500 chars),
  verdict, score, sandbox/honeypot details. No seed data.

## 10. Test corpus (`tests/corpus/`, Abhinav)

`corpus.jsonl`, one labelled request per line:

```json
{"id":"c-0001","label":"benign","owasp":null,"expected_verdict":"SAFE",
 "method":"GET","path":"/api/accounts/12","query":"","headers":{},"body":null,"notes":"owner views own account"}
```

- Malicious items come from **public, documented test cases** (OWASP Web Security
  Testing Guide, OWASP ZAP rule docs). Don't invent new attacks.
- `scenarios/full.yaml` lists steps for the demo: `[{step, corpus_ids, delay_ms}]` in the order of `docs/07-demo-script.md`.

## 11. Postgres (Jerush, migrations in `analyst/migrations/`)

```sql
CREATE TABLE events (id uuid PRIMARY KEY, ts timestamptz, source text, verdict text,
  owasp text, rule_id text, score real, correlation_id text, data jsonb);
CREATE INDEX ON events (ts DESC);
CREATE TABLE rules (id text PRIMARY KEY, owasp text, source text, enabled bool,
  hits int DEFAULT 0, created_at timestamptz, data jsonb);
```
