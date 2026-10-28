# Akchhat — everything visible: bank, honeypot, dashboard

You own what the judges actually see: the demo bank (VulnBank), its honeypot twin,
and the live dashboard. You also own the slides and clips.

**Your folders (edit only these):** `bank/`, `honeypot/`, `dashboard/`
**Read first:** `AGENTS.md`, `docs/01-overview.md`, `docs/04-system-design.md` sections 2, 5, 8

---

## Updates from Jerush (read these first, newest at the top)

### 2026-10-28 — P2 integration (G2 green locally): Jerush finished your open P1/P2 items
Your branch hadn't merged `main` and only changed the checklist and README, so Jerush completed these in integration.
**Merge `origin/main` before you change anything in your folders**, or you'll get conflicts.

- **Dashboard is now React + Vite + TypeScript + Tailwind** (`dashboard/src/`): `types.ts` mirrors the contracts, and `App.tsx` has:
  - the live feed over `/ws/live`, with auto-reconnect
  - verdict colours and OWASP chips with names
  - a source label (HONEYPOT/SANDBOX) on events that have no verdict
  - totals, the 10 OWASP tiles (A03/A04/A08 marked "on slide"), rules with an On/Off toggle, and timers
  `public/index.html` (the static page) was removed. The `Dockerfile` is now a Node 20 build stage plus nginx.
  `npm test` runs the type check. Dev loop: `cd dashboard && npm install && npm run dev`.
- `dashboard/README.md`: restored. It had been saved in a non-UTF-8 encoding (the `—` turned into `ù`) and had lost its content.
  **Save files as UTF-8** (VS Code: bottom-right encoding → "Save with Encoding" → UTF-8).
- `honeypot/app/main.py`: events are now `shared.schemas.Event` sent with `shared.events.emit`, using one async Redis client
  created at startup (no more sync connection per request). `honeypot/Dockerfile` copies `shared/` and sets `PYTHONPATH`.
- `bank/Dockerfile`: copies `shared/` (your unticked P1 item) and sets `PYTHONPATH`.
- Tests: `bank/tests/` (seed counts, login, owner field, transfer, search and memo) and `honeypot/tests/` (route shapes,
  shared-schema event with `correlation_id`, no `/health` events). Run them with `docker compose run --rm bank pytest -q` (same for honeypot).

**Your next steps (P3, due at G3):**
1. [ ] `git fetch origin && git merge origin/main`, then `docker compose down -v && docker compose up --build -d` and open http://localhost:3000.
2. [ ] Read `dashboard/src/App.tsx` so you own it. It's yours to restyle.
3. [ ] P3 items in Part 2 below: the scoreboard and rules toggle exist already, so polish them. Make the
       "first seen → blocked" timer the big moment (it fills in when Jerush's `/api/timers` lands in P3).
4. [ ] Start the slide deck and the A03/A04/A08 clips early (P4). They take longer than you think.

### 2026-10-28 — `/ws/live` is live
- `/ws/live` now pushes `{"type":"event"}` for every saved event, `{"type":"rule"}` when a rule changes,
  and `{"type":"stats"}` at most once a second. Your current page already updates live; the Refresh button is no longer needed.
- For your P2 honeypot: G2 (`tests/e2e/test_g2.py`) needs your honeypot event to carry the **same `correlation_id`**
  as the gateway's `X-Request-Id` (you already read the `x-request-id` header, so keep that).

### 2026-10-28 — P1 integration (G1 green, on `main`, tagged `g1-core`)

**Your next steps, in order:**
1. [ ] Get the integrated code: `git checkout feat/akchhat-bank-dashboard && git fetch origin && git merge origin/main`
       (this brings in Jerush's P0 skeleton and the fixes above; take `main`'s version if anything conflicts).
2. [ ] Check it runs: `docker compose down -v && docker compose up --build -d`, open http://localhost:3000, then `pytest tests/e2e -q`.
3. [ ] Clear the "Please do" list above (honeypot via `shared/`, one async Redis client, show `source` when there's no verdict, bank tests).
4. [ ] Start **P2** (Part 2 below, due at G2): full honeypot mirror with events, and the React + Vite + TS + Tailwind dashboard
       (`src/types.ts`, live feed over `/ws/live`, verdict colours, OWASP chips, nginx Dockerfile keeping the `resolver` lines).
   - Design note for the React rewrite: make headings clearly bigger than body text (at least 1.25× per step).
     It has to read on a projector at 1366×768.
5. [ ] Push to your branch whenever a piece works, and tell Jerush "ready to merge".

**New git workflow** (full version: `AGENTS.md` section 6, `docs/06-git-workflow.md`):
- You keep **one branch for the whole event**: `feat/akchhat-bank-dashboard`. Don't create others.
- Start every session with `git fetch origin && git merge origin/main`.
- When a task is done: commit only your folders, push to your branch, and tell Jerush "ready to merge".
- **Never rebase or force-push.** Jerush merges your branch, so its history must not change.
- Only Jerush pushes to `main`. You don't open PRs.

**What happened to your P1 work:** merged into `feat/jerush-analyst-core`, then pushed to `main`. G1 passes.
Your branch started before the P0 skeleton, so your files clashed with Jerush's stubs. **Your versions were kept**, except:
- `dashboard/nginx.conf`: Jerush's version is kept. **Keep these two lines** when you replace it for the Vite build:
  `resolver 127.0.0.11 valid=10s;` and `set $analyst http://analyst:8004;` (with `proxy_pass $analyst;`).
  Without them, nginx caches the analyst's IP and returns 502 after the analyst is recreated.

**Jerush fixed in your folders** (merge `origin/main` before you touch these files):
- `dashboard/public/index.html`: **security bug (XSS).** Event fields like `request.path` come from attackers and were
  inserted with `innerHTML` unescaped. Requesting `/<img src=x onerror=alert(1)>` would run script in the judges' dashboard.
  `text()` now HTML-escapes. Always wrap data in `text()`. In React, JSX escapes for you, so never use `dangerouslySetInnerHTML`.

- `honeypot/app/main.py`: the middleware turned Docker's `/health` checks (every 10 s) into events, which flooded the live feed.
  It now skips `/health`.

**Please do (not blocking G1):**
- [x] Honeypot: build events with `shared.schemas.Event` and send them with `shared.events.emit` (`AGENTS.md` section 3),
      instead of a hand-made dict. Add `COPY shared /app/shared` to `honeypot/Dockerfile`.
- [x] Honeypot: the middleware opens a **new sync Redis connection on every request**, inside async code, which blocks the server.
      Create one `redis.asyncio` client at startup and `await` the emit.
- [x] Dashboard: `addEvent` shows `event.verdict || "SAFE"`, but honeypot and sandbox events have **no verdict**, so they
      look like SAFE traffic. Show `event.source` instead (for example a grey "honeypot" chip) when `verdict` is null.
- [x] Bank: add a few tests in `bank/tests/` so `docker compose run --rm bank pytest -q` runs something
      (for example login with seed credentials, account lookup, transfer).
- [ ] Bank request bodies are now written in `docs/04-system-design.md` section 8. If you change one, tell Jerush and Abhinav (the corpus depends on them).
- [x] FYI: `/ws/live` now pushes events, rules and stats live (see the newest update).

---

## Part 1 — Set up your laptop (about 40 min)

You don't need Kaggle, the homelab or any secrets. Everything runs locally in mock mode.

### Windows 10/11

1. **WSL2.** Open PowerShell as Administrator:
   ```powershell
   wsl --install -d Ubuntu-24.04
   ```
   Reboot, open "Ubuntu" from the Start menu, and create a username and password.
2. **Docker Desktop.** Install it from https://www.docker.com/products/docker-desktop/.
   - Settings → General → tick "Use the WSL 2 based engine".
   - Settings → Resources → WSL Integration → enable "Ubuntu-24.04".
   - Settings → Resources → give Docker at least 4 GB memory if you have a slider.
3. **Inside Ubuntu (WSL)**, install the tools:
   ```bash
   sudo apt update && sudo apt install -y git python3 python3-venv python3-pip make curl
   # Node 20 LTS via nvm
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
   source ~/.bashrc && nvm install 20 && nvm use 20
   git config --global user.name "Akchhat"
   git config --global user.email "<your github email>"
   ```
4. **VS Code extensions:** "WSL", "Python", "Docker", "ESLint", "Prettier", "Tailwind CSS IntelliSense". Then:
   ```bash
   mkdir -p ~/code && cd ~/code
   git clone https://github.com/Hackfest-X-Saividya/hackstreet-boys-t2-08.git
   cd hackstreet-boys-t2-08 && code .
   ```
   Keep the repo inside WSL (`~/code`), not in `C:\`. Docker and `npm` are much faster that way.
5. **GitHub login.** Run `gh auth login` (install with `sudo apt install gh`), or set up an SSH key.
   Accept Jerush's collaborator invite.

### macOS

```bash
brew install git python@3.11 node@20 gh
brew install --cask docker visual-studio-code
gh auth login
```
Open Docker Desktop once and let it finish starting.

### Check it works

```bash
cp .env.example .env
docker compose up --build
curl localhost:8001/health        # bank
curl localhost:8002/health        # honeypot
```
Open http://localhost:3000 for the dashboard placeholder.

**Fast dashboard dev loop** (hot reload, with the rest of the stack running in Docker):
```bash
cd dashboard && npm install && npm run dev     # http://localhost:5173, proxies /api and /ws to :8004
```

**Low on RAM?** Run only what you need:
```bash
docker compose up --build redis postgres mock-llm analyst bank honeypot
```

### Your coding agent

Start each session with:
> "Read AGENTS.md and team/AKCHHAT.md. I am Akchhat. Only edit bank/, honeypot/ and dashboard/."

---

## Part 2 — Your tasks

Tick boxes as you go (this file is the one place outside your folders you may edit).

### P1 — Core path (H1–6) · due at G1
- [x] `bank/app/main.py`: FastAPI app with every route in the design doc's bank table (section 8), returning JSON
- [x] SQLite schema: customers, accounts, transactions, staff, sessions
- [x] `bank/seed.py` with Faker: 50 customers, 120 accounts, 2,000 transactions, 3 staff (1 admin). Runs on container start if the DB is empty.
- [x] The intentional weaknesses listed in the table. Keep each one small and commented with `# DEMO-WEAKNESS: A0x`, so it's obvious and easy to show judges.
- [x] Support chat: a **mock bot** (rule-based replies, no real LLM) whose hidden prompt contains a fake "internal note"
- [x] The bank must never call the internet: statement fetch uses an httpx client with a 2 s timeout, and the network is internal-only anyway
- [x] `bank/Dockerfile` (build context = repo root, `COPY shared /app/shared`) (done by Jerush in integration)
- [x] `honeypot/`: stub with the same routes, returning `{"ok":true}`

### P2 — Honeypot + live feed (H6–12) · due at G2
- [x] Honeypot: the same routes and response *shapes* as the bank, with separate fake data and no real effects (transfers "succeed" but change nothing)
- [x] Honeypot emits an event per request: `source="honeypot"`, `details={"route","action"}`
- [x] Dashboard (React + Vite + TS + Tailwind): `src/types.ts` mirroring `Event`/`Rule`/stats from the design doc (done by Jerush in integration)
- [x] Live feed page: connect to `/ws/live`, newest first, green/amber/red by verdict, OWASP chip, rule id, path (React, done by Jerush in integration)
- [x] `dashboard/Dockerfile`: build with Node, serve with nginx; nginx proxies `/api` and `/ws` to `analyst:8004` (done by Jerush in integration)

### P3 — Scoreboard + timer (H12–18) · due at G3
- [ ] OWASP scoreboard: 10 tiles (A01–A10 with names from the design doc). A tile lights up when it has a DIVERT or DENY. A03, A04 and A08 are marked "on slide".
- [ ] Rules panel: list from `/api/rules`, with learned rules highlighted and an enable/disable toggle (`PATCH`)
- [ ] "First seen → blocked" timer from `/api/timers`. Big number, shown when a learned rule first blocks.
- [ ] Totals bar: SAFE / DIVERT / DENY counts from `/api/stats`

### P4 — Demo polish (H18–22) · due at G4 (feature freeze)
- [ ] Run scenario button → `POST /api/scenario/run`, with a progress indicator per step
- [ ] Layout readable on a projector: big type, high contrast, works at 1366×768
- [ ] Slide deck (problem → three verdicts → architecture → OWASP coverage → live demo → results)
- [ ] 3 short screen-recorded clips: A03 dependency scan result, A04 plain-HTTP login flagged, A08 tampered token rejected
- [ ] Prepare your speaking part: step 1 of the demo and the slide intro

---

## Interfaces you depend on

| From | What | Where |
|---|---|---|
| Jerush | `/api/*` and `/ws/live` on the analyst | design doc section 8, analyst |
| Jerush | `shared/schemas.py`, `shared/events.emit` | sections 4–5 |
| Abhinav | The gateway sits in front of your bank: all real traffic arrives via `gateway:8000` | section 1 |

## Requests to Jerush / Abhinav

_Write requests here (date, what, why). The owner makes the change._

-
