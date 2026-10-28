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
| Kaggle #2 | Defense LLM, OpenAI-compatible server, behind `defense.jrushvj.dev` |
| Kaggle #1 | Optional: generates rewordings of corpus items for the runner (never free-form attacks) |
| Cloudflare | Tunnels `defense.jrushvj.dev` (API key) and `demo.jrushvj.dev` (Cloudflare Access, team emails only) |

## Tasks

### P0 — Skeleton (H0–1) · gate G0
- [ ] Push these docs to `Hackfest-X-Saividya/hackstreet-boys-t2-08`, protect `main`
- [ ] Folder skeleton with a `README.md` in each folder (already drafted)
- [ ] `shared/schemas.py`, `owasp.py`, `events.py`, `config.py` exactly as in design doc sections 4–6
- [ ] Stub FastAPI app in every Python service with `/health` and fixed-JSON contract endpoints
- [ ] Placeholder dashboard (static nginx page) so port 3000 answers
- [ ] `mock-llm` with canned `RuleProposal`s per OWASP id
- [ ] `docker-compose.yml` (networks `edge` + `internal` with `internal: true`, memory limits, health checks), `docker-compose.override.yml` (dev ports + edge attach), `.env.example`, `.gitignore`
- [ ] `.github/CODEOWNERS` `.github/pull_request_template.md`
- [ ] Confirm both teammates have the stack running → tag `p0-skeleton`

### P1 — Core path (H1–6) · gate G1
- [ ] `analyst/migrations/001_init.sql` (design doc section 11); run on start
- [ ] Stream consumer: consumer group on `events`, persist to Postgres, update stats
- [ ] At start: load `gateway/rules/packs/*.yaml` (mounted read-only into `analyst` by compose at `/app/packs`) → Postgres + Redis `rules:active`, publish `rules:updated`
- [ ] `/api/events`, `/api/stats`, `/api/rules`
- [ ] `tests/e2e/test_g1.py`; merge, test, tag `g1-core`

### P2 — DIVERT + infra (H6–12) · gate G2
- [ ] `WS /ws/live` broadcasting events, rules and stats
- [ ] `kaggle/defense.ipynb`: llama.cpp server (OpenAI API) with your chosen model, an API key, and a Cloudflare tunnel to `defense.jrushvj.dev`
- [ ] `infra/homelab.md`: deploy steps; first homelab deploy of `g1-core`
- [ ] `tests/e2e/test_g2.py`; merge, test, tag `g2-divert`

### P3 — Learning loop (H12–18) · gate G3
- [ ] DIVERT handler: collect gateway + sandbox + honeypot events by `correlation_id` (wait up to 2 s), build the prompt, call the LLM
- [ ] Validator: schema, regex compiles, length 3–300, false-positive replay over the last 500 SAFE events (≤ 1%)
- [ ] Store the rule (`L-xxxxxxxx`), push to Redis, publish; retry once, then canned fallback
- [ ] `/api/timers` (first DIVERT of the pattern → rule created → first DENY by that rule)
- [ ] `LLM_MODE=local` against llama.cpp on the homelab GPU; `DEMO_OFFLINE=1` canned path
- [ ] `tests/e2e/test_g3.py`; merge, test, tag `g3-learning`

### P4 — Demo hardening (H18–22) · gate G4 (feature freeze)
- [ ] `runner/`: `/run` + `/runs/{id}`, reads `scenarios/full.yaml`, target allowlist check before every send
- [ ] `/api/scenario/run` → runner; `analyst/reset_demo.py` (truncate events, drop learned rules)
- [ ] Deploy `demo-ready` to homelab; `demo.jrushvj.dev` behind Cloudflare Access
- [ ] Record the full fallback video
- [ ] 3 clean full runs → tag `demo-ready`

### P5 — Rehearsal (H22–24)
- [ ] Two timed rehearsals, test `DEMO_OFFLINE=1`, check the hotspot path
- [ ] Your speaking parts: steps 5–7

## Merge procedure at every gate

```bash
git checkout main && git pull
# merge PRs on GitHub in order: shared → Abhinav → Akchhat → Jerush
git pull
docker compose down -v && docker compose up --build -d
pytest tests/e2e -q
git tag <gate-tag> && git push --tags
# then post in the group chat: "Gate <n> green, pull main"
```

## Requests from teammates

Check the "Requests to Jerush" sections in `team/ABHINAV.md` and `team/AKCHHAT.md` every hour.
