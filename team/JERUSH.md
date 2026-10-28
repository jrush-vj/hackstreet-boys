# Jerush — integration lead: infra, contracts, AI, deploy

You own everything shared and everything that touches your homelab, Kaggle and Cloudflare.
You're also the only person who merges to `main`.

**Your folders:** `shared/`, `analyst/`, `runner/`, `mock-llm/`, `kaggle/`, `infra/`, `tests/e2e/`,
`docker-compose.yml`, `docker-compose.override.yml`, `.env.example`, `.gitignore`, `.github/`, `docs/`, `AGENTS.md`, `CLAUDE.md`

## Machines you run

| Machine | Use |
|---|---|
| Your laptop (Claude Code) | Merging, e2e tests, building and tagging releases |
| Homelab LOQ | `docker compose -f docker-compose.yml up -d` on tagged builds; local fallback LLM (llama.cpp on the RTX 4060, port 8080) |
| Kaggle #2 | Defense LLM, OpenAI-compatible server, behind a `*.trycloudflare.com` quick tunnel (no domain) |
| Kaggle #1 | Optional: generates rewordings of corpus items for the runner (never free-form attacks) |
| Cloudflare | Tunnel `demo.jrushvj.dev` (Cloudflare Access, team emails only) |

## ▶ CURRENT (updated 2026-10-29, after G3)

`main` = everyone's P1 + P2 + P3, tagged `g3-learning`, 30/30 e2e green (mock mode).
1. [ ] Kaggle: run your Qwen3-14B notebook, paste the trycloudflare URL + key in the honeypot console (⚙), "Test connection",
       then run `pytest tests/e2e/test_g3.py -q` once against it (G3 in kaggle mode).
2. [ ] P4: `runner/` (`/run`, `/runs/{id}`, reads `scenarios/full.yaml`, target allowlist before every send),
       `/api/scenario/run` → runner plus a progress endpoint for Akchhat's button.
3. [ ] Homelab deploy of `g3-learning` (`infra/homelab.md`), fallback video, 3 clean full runs → `demo-ready`.
4. [ ] Every hour: look for `READY TO MERGE` lines under "Requests to Jerush" in both team files.

## Tasks

### P0 — Skeleton (H0–1) · gate G0
- [x] Push these docs to `Hackfest-X-Saividya/hackstreet-boys-t2-08`, protect `main`
- [x] Folder skeleton with a `README.md` in each folder (already drafted)
- [x] `shared/schemas.py`, `owasp.py`, `events.py`, `config.py` exactly as in design doc sections 4–6
- [x] Stub FastAPI app in every Python service with `/health` and fixed-JSON contract endpoints
- [x] Placeholder dashboard (static nginx page) so port 3000 answers
- [x] `mock-llm` with canned `RuleProposal`s per OWASP id
- [x] `docker-compose.yml` (networks `edge` + `internal` with `internal: true`, memory limits, health checks), `docker-compose.override.yml` (dev ports + edge attach), `.env.example`, `.gitignore`
- [x] `.github/CODEOWNERS` `.github/pull_request_template.md`
- [x] Confirm both teammates have the stack running → tag `p0-skeleton`

### P1 — Core path (H1–6) · gate G1
- [x] `analyst/migrations/001_init.sql` (design doc section 11); run on start
- [x] Stream consumer: consumer group on `events`, persist to Postgres, update stats
- [x] At start: load `gateway/rules/packs/*.yaml` (mounted read-only into `analyst` by compose at `/app/packs`) → Postgres + Redis `rules:active`, publish `rules:updated`
- [x] `/api/events`, `/api/stats`, `/api/rules`
- [x] `tests/e2e/test_g1.py`; merge, test, tag `g1-core`

### P2 — DIVERT + infra (H6–12) · gate G2
- [x] `WS /ws/live` broadcasting events, rules and stats
- [ ] `kaggle/defense.ipynb`: llama.cpp server (OpenAI API) with your chosen model, an API key, and a Cloudflare quick tunnel (`*.trycloudflare.com`) (notebook written; **run it on Kaggle #2** with secret `DEFENSE_LLM_KEY`)
- [ ] `infra/homelab.md`: deploy steps; first homelab deploy of `g1-core` (steps written; **deploy not done yet**)
- [x] `tests/e2e/test_g2.py`; merge, test, tag `g2-divert`

### P3 — Learning loop (H12–18) · gate G3
- [x] DIVERT handler: collect gateway + sandbox + honeypot events by `correlation_id` (wait up to 2 s), build the prompt, call the LLM (`analyst/app/learner.py`)
- [x] Validator: schema, regex compiles, length 3–300, false-positive replay over the last 500 SAFE events (≤ 1%), and it must match the triggering request
- [x] Store the rule (`L-xxxxxxxx`), push to Redis, publish; retry once, then canned fallback (`shared/canned.py`)
- [x] `/api/timers` (first DIVERT of the pattern → rule created → first DENY by that rule)
- [ ] `LLM_MODE=local` against llama.cpp on the homelab GPU (code path done, **not run on the GPU yet**); `DEMO_OFFLINE=1` canned path (done; tested via the console's "AI off")
- [x] `tests/e2e/test_g3.py` (zero-day, offline path, /analyze, sandbox stack trace); merge, test. Tag `g3-learning` when pushed

### P4 — Demo hardening (H18–22) · gate G4 (feature freeze)
- [ ] `runner/`: `/run` + `/runs/{id}`, reads `scenarios/full.yaml`, target allowlist check before every send
- [ ] `/api/scenario/run` → runner; `analyst/reset_demo.py` (truncate events, drop learned rules)
- [ ] Deploy `demo-ready` to homelab; `demo.jrushvj.dev` behind Cloudflare Access
- [ ] Record the full fallback video
- [ ] 3 clean full runs → tag `demo-ready`

### P5 — Rehearsal (H22–24)
- [ ] Two timed rehearsals, test `DEMO_OFFLINE=1`, check the hotspot path
- [ ] Your speaking parts: steps 5–7

## Merge procedure (every time a teammate says "ready to merge", and at every gate)

See the integration loop in `docs/06-git-workflow.md`. Push to `main` only when the stack is healthy
and all service tests + `tests/e2e` pass. At a gate, also `git tag <gate-tag> && git push --tags`.

## Requests from teammates

Check the "Requests to Jerush" sections in `team/ABHINAV.md` and `team/AKCHHAT.md` every hour. A `READY TO MERGE` line means: run the integration loop. After pushing `main`, rewrite their "▶ CURRENT" blocks.
