# AGENTS.md — rules for every coding agent on this repo

Read this file fully before writing any code. These rules exist so three people
(and their agents) can work in parallel for 24 hours without merge conflicts.

## 1. Find out who you are working for

Ask your human which team member they are, or check `git config user.name`. Then
read their file in `team/` (`ABHINAV.md`, `AKCHHAT.md` or `JERUSH.md`). That file
lists the folders you may edit and the tasks to do.

## 2. Folder ownership (hard rule)

| Folder / file | Owner | Others may edit? |
|---|---|---|
| `shared/`, `docker-compose.yml`, `docker-compose.override.yml`, `.env.example`, `.gitignore`, `.github/`, `analyst/`, `runner/`, `mock-llm/`, `kaggle/`, `infra/`, `tests/e2e/`, `AGENTS.md`, `CLAUDE.md`, `docs/` | Jerush | No |
| `gateway/`, `sandbox/`, `tests/corpus/` | Abhinav | No |
| `bank/`, `honeypot/`, `dashboard/` | Akchhat | No |
| `team/<NAME>.md` | That person | Only to tick their own checkboxes |

- Edit files **only** inside your human's folders.
- If you need a change elsewhere (a new field in `shared/schemas.py`, a new env
  var, a compose change), **stop and write it up** as a note under
  "Requests to Jerush" in your human's `team/<NAME>.md`, or tell your human
  to message the owner. Do not make the change yourself.
- Never create new top-level folders or files.

## 3. Contracts are law

`docs/04-system-design.md` defines ports, the event schema, the rule schema and
every HTTP endpoint. `shared/schemas.py` is the code version of it.

- Import models from `shared/schemas.py`; never redefine them locally (the
  dashboard is the only exception: `dashboard/src/types.ts` mirrors them).
- Don't rename fields, change types or add required fields. Optional fields
  need a request to Jerush first.
- If the doc and the code disagree, the doc wins. Flag it to your human.

## 4. Dependencies

- Python services: add packages only to `<your-service>/requirements.txt`, pinned
  (`fastapi==0.115.*` style).
- Dashboard: only `dashboard/package.json`.
- Never touch the root of the repo for dependency files.

## 5. Running and testing

- Default mode is `LLM_MODE=mock`, so no Kaggle, homelab or secrets are needed.
- Run your service's tests: `docker compose run --rm <service> pytest -q`
  (dashboard: `npm test` inside `dashboard/`).
- Before declaring a task done: `docker compose up --build` must start with no
  crash, and `GET /health` on your services must return `{"status":"ok"}`.

## 6. Git

- Branch: `feat/<owner>-<short-thing>`, for example `feat/abhinav-rate-rules`.
- Small commits, message format `<service>: <what changed>`.
- Rebase on `origin/main` before opening a PR. Never force-push `main`.
- Never commit `.env`, keys, tokens, model files or the SQLite DB.
- Full process: `docs/06-git-workflow.md`.

## 7. Safety rules for this project

This repo contains a **deliberately weak demo bank** for a defense demo.

- The bank and honeypot must only be reachable through the gateway on the
  internal Docker network. Never publish their ports to the host in production
  compose, never expose them through a tunnel.
- The bank's network is marked `internal: true` and can't reach the internet. Don't change that.
- Test traffic may only target `http://gateway:8000` (or `localhost:8000`).
  Any script that sends traffic must check the target before each send.
- Seed data is fake (Faker). Never put real personal data anywhere.
- Don't write new attack tooling. Test cases come from the labelled corpus in
  `tests/corpus/` (see `docs/04-system-design.md`).

## 8. Style

- Python 3.11, FastAPI, Pydantic v2, type hints, `ruff` formatting.
- Log JSON lines to stdout. Never print secrets.
- Keep it simple. This is a 24-hour build, so no frameworks beyond what's listed.
