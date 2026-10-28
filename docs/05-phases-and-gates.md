# 05 — Phases, deliverables and gates

Hours are counted from build start (H0). At each **gate** everyone stops pushing,
Jerush merges everyone's branch into his on his laptop (`docs/06-git-workflow.md`), runs `docker compose up --build` +
`tests/e2e/`, and tags the result. Nobody starts the next phase's features until the
gate is green. Bug fixes for the current phase can continue.

| Phase | Hours | Gate at end | Tag |
|---|---|---|---|
| P0 Skeleton | H0–1 | G0 | `p0-skeleton` |
| P1 Core path | H1–6 | G1 | `g1-core` |
| P2 DIVERT path + infra | H6–12 | G2 | `g2-divert` |
| P3 Learning loop | H12–18 | G3 | `g3-learning` |
| P4 Demo hardening | H18–22 | G4 (feature freeze) | `demo-ready` |
| P5 Rehearsal | H22–24 | — | `final` |

---

## P0 — Skeleton (H0–1) · Jerush

**Work**
- Jerush: repo, `shared/`, `docker-compose.yml` + override, `.env.example`, a stub of every
  service (FastAPI app with `/health` and fixed-JSON endpoints matching the contracts), `mock-llm`.
- Abhinav and Akchhat: set up laptops (see `team/<NAME>.md`), clone, run the stack.

**You get after P0**
- `git clone && docker compose up --build` works on all three laptops.
- Every service answers `/health`, and every contract endpoint returns fixed JSON.
- The dashboard placeholder page loads at http://localhost:3000.

**G0 check:** all three laptops show all containers healthy.

---

## P1 — Core path (H1–6)

**Work**
- Abhinav: gateway proxy, rule engine (regex + path), the 3 rule packs, first 40 corpus items.
- Akchhat: VulnBank routes with seed data, the Dockerfile, honeypot stub that echoes route names.
- Jerush: Postgres migrations, analyst stream consumer that persists events, `/api/events`, `/api/stats`, loading rule packs into Redis.

**You get after P1**
- Banking requests through `localhost:8000` return real seeded data as SAFE.
- Rule-pack hits return DENY with the A05 tag.
- Every request is stored in Postgres, and `/api/stats` counts verdicts.

**G1 check:** `tests/e2e/test_g1.py` passes (SAFE path, the 3 pack DENYs, events persisted).

---

## P2 — DIVERT path + infra (H6–12)

**Work**
- Abhinav: rate rules (A07 login burst, A06 transfer burst), path rules (A01, A02),
  anomaly score v1, sandbox `/replay`, DIVERT routing to the honeypot.
- Akchhat: honeypot with full route mirror + events; dashboard live feed over `/ws/live`, verdict colours, OWASP tag chips.
- Jerush: `/ws/live`, Kaggle #2 defense LLM server, Cloudflare tunnel `defense.jrushvj.dev`,
  first homelab deploy of `g1-core`.

**You get after P2**
- Suspicious requests are DIVERTed, the honeypot answers, and the sandbox reports status/errors.
- The dashboard shows a live coloured feed.
- The defense LLM answers through the tunnel, and the homelab runs the integrated stack.

**G2 check:** `tests/e2e/test_g2.py` passes (a DIVERT produces gateway + honeypot + sandbox
events with the same `correlation_id`; A01, A02 and A07 DENY).

---

## P3 — Learning loop (H12–18)

**Work**
- Jerush: analyst DIVERT → LLM → validate → false-positive check → store → publish;
  `/api/timers`; `LLM_MODE=local` fallback on the RTX 4060; `DEMO_OFFLINE` canned rules.
- Abhinav: anomaly score v2 (tuned on the corpus), gateway hot-reload on `rules:updated` (under 1 s), sandbox `stack_trace_leaked` detection (A10).
- Akchhat: OWASP 10-tile scoreboard, rules list with enable/disable, "first seen → blocked" timer.

**You get after P3**
- **The zero-day moment works:** an unseen A06 transfer-abuse pattern is DIVERTed, a rule is learned
  and shown on the dashboard, and the next similar request is DENYed. The timer shows the seconds.
- It works in all three LLM modes.

**G3 check:** `tests/e2e/test_g3.py` passes in `mock` mode. Jerush runs it manually in `kaggle` and `local` modes.

---

## P4 — Demo hardening (H18–22) · feature freeze at H22

**Work**
- Jerush: runner + `scenarios/full.yaml` wiring, "Run scenario" end to end, homelab deploy,
  `demo.jrushvj.dev` behind Cloudflare Access, fallback screen recording.
- Abhinav: complete corpus for all 7 live steps, threshold tuning so SAFE traffic never trips.
- Akchhat: Run scenario button + progress, polish, slide deck, 3 clips (A03, A04, A08).

**You get after P4**
- One button plays the full timed demo on the homelab, visible at `demo.jrushvj.dev`.
- The slides and clips are done, and a fallback video is recorded. The `demo-ready` tag is deployed.

**G4 check:** 3 full scenario runs in a row with no failure. After G4: only fixes Jerush approves.

---

## P5 — Rehearsal (H22–24)

**You get after P5**
- Two timed rehearsals (under the slot length), and a tested `DEMO_OFFLINE=1` run.
- A hotspot is ready, and everyone knows their speaking part (`docs/07-demo-script.md`).
