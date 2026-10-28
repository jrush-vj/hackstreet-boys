## What
<!-- one or two lines -->

## Owner check
- [ ] I only changed files in my own folders (see AGENTS.md section 2)
- [ ] No changes to `shared/`, compose files or `.env.example` (or Jerush asked for them)
- [ ] No secrets, `.env`, DB files or model files committed

## Contract check
- [ ] Events and rules match `docs/04-system-design.md`
- [ ] `GET /health` still returns `{"status":"ok"}`

## Tested
- [ ] `docker compose up --build` starts cleanly
- [ ] My service's tests pass: `docker compose run --rm <service> pytest -q` / `npm test`

## Phase / task
<!-- e.g. P2 — honeypot event emission (team/AKCHHAT.md) -->
