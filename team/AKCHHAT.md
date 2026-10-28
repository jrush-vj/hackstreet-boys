# Akchhat — everything visible: bank, honeypot, dashboard

You own what the judges actually see: the demo bank (VulnBank), its honeypot twin,
and the live dashboard. You also own the slides and clips.

**Your folders (edit only these):** `bank/`, `honeypot/`, `dashboard/`
**Read first:** `AGENTS.md`, `docs/01-overview.md`, `docs/04-system-design.md` sections 2, 5, 8

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
- [ ] `bank/Dockerfile` (build context = repo root, `COPY shared /app/shared`) — pending: the current image copies only the bank package.
- [x] `honeypot/`: stub with the same routes, returning `{"ok":true}`

### P2 — Honeypot + live feed (H6–12) · due at G2
- [x] Honeypot: the same routes and response *shapes* as the bank, with separate fake data and no real effects (transfers "succeed" but change nothing)
- [x] Honeypot emits an event per request: `source="honeypot"`, `details={"route","action"}`
- [ ] Dashboard (React + Vite + TS + Tailwind): `src/types.ts` mirroring `Event`/`Rule`/stats from the design doc
- [x] Live feed page: connect to `/ws/live`, newest first, green/amber/red by verdict, OWASP chip, rule id, path (static dashboard implementation)
- [ ] `dashboard/Dockerfile`: build with Node, serve with nginx; nginx proxies `/api` and `/ws` to `analyst:8004` — pending: current image serves the static page directly.

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
