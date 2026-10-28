# 02 — Requirements

## Functional

| ID | Requirement | Owner |
|---|---|---|
| F1 | Gateway proxies every request to the bank and returns a SAFE / DIVERT / DENY verdict | Abhinav |
| F2 | Gateway loads predefined rule packs (SQL, prompt, log injection) from YAML at start | Abhinav |
| F3 | Gateway applies rate rules (per IP, per account) and path rules (admin/debug, other-account access) | Abhinav |
| F4 | Gateway computes an anomaly score 0–1; ≥ `DIVERT_THRESHOLD` (default 0.7) means DIVERT | Abhinav |
| F5 | Gateway picks up new rules from Redis within 1 s of `analyst` publishing them | Abhinav |
| F6 | Sandbox replays a DIVERTed request against a throwaway bank copy and reports status, error and latency | Abhinav |
| F7 | VulnBank offers login, accounts, transfer, search, memo, support chat, statement fetch, admin, debug | Akchhat |
| F8 | VulnBank is seeded with fake data: 50 customers, 120 accounts, 2,000 transactions, 3 staff | Akchhat |
| F9 | Honeypot mirrors the bank's routes with fake data and logs every interaction as an event | Akchhat |
| F10 | Dashboard shows live feed, OWASP 10-tile scoreboard, rules list, "first seen → blocked" timer, Run scenario button | Akchhat |
| F11 | Every service emits events in the shared event schema to Redis stream `events` | All |
| F12 | Analyst consumes DIVERT and sandbox/honeypot events, asks the defense LLM for a rule, validates it and stores it | Jerush |
| F13 | Analyst exposes read APIs + WebSocket for the dashboard | Jerush |
| F14 | Runner replays the labelled corpus at the gateway in a fixed, timed order | Jerush |
| F15 | `LLM_MODE` switches between `mock`, `kaggle` and `local` with no code change | Jerush |

## Non-functional

| ID | Requirement |
|---|---|
| N1 | Gateway verdict on cached rules: p95 under 5 ms (excluding upstream bank time) |
| N2 | DIVERT → learned rule active: under 15 s with Kaggle, under 30 s with the local model |
| N3 | A learned rule is rejected if it would match more than 1% of the last 500 SAFE requests |
| N4 | Whole stack starts with `docker compose up --build` on an 8 GB laptop in mock mode |
| N5 | Bank and honeypot are reachable only via the gateway; the bank network has no internet access |
| N6 | No real personal data; no secrets in git |
| N7 | Every service has `GET /health` returning `{"status":"ok"}` |
| N8 | Demo runs fully offline with `DEMO_OFFLINE=1` (canned LLM responses) |

## In scope

- OWASP 2025 A01, A02, A05, A06, A07, A09 and A10 live; A03, A04 and A08 on a slide
- A single-host Docker deployment (laptops in dev, the homelab LOQ for the demo)

## Out of scope

- Network-layer attacks, DDoS mitigation, malware analysis
- Production hardening, multi-tenant, auth for the dashboard beyond Cloudflare Access
- Generating novel attacks. Test traffic comes only from the labelled corpus.
