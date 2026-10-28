# Abhinav — detection: gateway, sandbox, corpus

You own the brain of the defense: the gateway that gives every request a verdict, the
sandbox that replays suspicious ones safely, and the labelled test corpus.

**Your folders (edit only these):** `gateway/`, `sandbox/`, `tests/corpus/`
**Read first:** `AGENTS.md`, `docs/04-system-design.md` sections 2, 5–8 and 10

---

## Updates from Jerush (read these first, newest at the top)

### 2026-10-28 — P1 integration
**New git workflow** (full version: `AGENTS.md` section 6, `docs/06-git-workflow.md`):
- You keep **one branch for the whole event**: `feat/abhinav-p1-gateway`. Don't create others.
- Start every session with `git fetch origin && git merge origin/main`.
- When a task is done: commit only your folders, push to your branch, and tell Jerush "ready to merge".
- **Never rebase or force-push.** Jerush merges your branch, so its history must not change.
- Only Jerush pushes to `main`. You don't open PRs.

**What happened to your P1 work:** merged into `feat/jerush-analyst-core`, then into `main`.
G1 passes. Your gateway tests pass 5/5. The `DeprecationWarning` comes from Starlette itself and is harmless.

**Jerush changed in your folders** (merge `origin/main` before you touch these files):
- `tests/corpus/corpus.jsonl`: the bank rejected 3 SAFE items with 422 because their bodies didn't match the bank.
  - `c-0002`, `c-0016` (login) now send `{"email": "customer1@example.test" / "customer2@...", "password": "password123"}`
  - `c-0011` (transfer) now sends `{"from_account_id": 3, "to_account_id": 18, "amount": 25.0}`

**Do this from now on:**
- [ ] Use the bank request bodies in `docs/04-system-design.md` section 8 (new table) for every corpus item,
      especially the P2 login-burst (A07) and transfer-burst (A06) items. Seed logins: `customer<N>@example.test` / `password123`.
- [ ] `tests/e2e/test_g1.py` now also requires every SAFE item to return a status below 400, not just `X-Verdict: SAFE`.
- [ ] `rules:updated` can carry a rule id or `*`, and `rules:active` holds enabled rules only. Your gateway already handles both.

---

## Part 1 — Set up your laptop (about 30 min)

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
   sudo apt update && sudo apt install -y git python3.11 python3.11-venv python3-pip make
   git config --global user.name "Abhinav"
   git config --global user.email "<your github email>"
   ```
   If `python3.11` isn't found, use `sudo add-apt-repository ppa:deadsnakes/ppa` first, or just use
   the default `python3` (3.12 is fine for local tools, since the containers use 3.11).
4. **VS Code extensions:** "WSL", "Python", "Docker", "Ruff". Then from the Ubuntu terminal:
   ```bash
   mkdir -p ~/code && cd ~/code
   git clone https://github.com/Hackfest-X-Saividya/hackstreet-boys-t2-08.git
   cd hackstreet-boys-t2-08 && code .
   ```
   Keep the repo inside WSL (`~/code`), not in `C:\`. Docker file sharing is much faster that way.
5. **GitHub login.** Run `gh auth login` (install with `sudo apt install gh`), or set up an SSH key.
   Accept Jerush's collaborator invite.

### macOS

```bash
brew install git python@3.11 gh
brew install --cask docker visual-studio-code
gh auth login
```
Open Docker Desktop once and let it finish starting.

### Check it works

```bash
cp .env.example .env
docker compose up --build
# in another terminal:
curl localhost:8000/health        # {"status":"ok"}
curl localhost:8003/health        # sandbox
```
Open http://localhost:3000 and you should see the dashboard placeholder. If something fails, post the
error in the group chat before trying to fix compose files (they're Jerush's).

**Low on RAM?** Run only what you need:
```bash
docker compose up --build redis postgres mock-llm analyst bank bank-sandbox honeypot gateway sandbox
```

### Your coding agent

Point your agent at the repo root and start each session with:
> "Read AGENTS.md and team/ABHINAV.md. I am Abhinav. Only edit gateway/, sandbox/ and tests/corpus/."

---

## Part 2 — Your tasks

Tick boxes as you go (this file is the one place outside your folders you may edit).

### P1 — Core path (H1–6) · due at gate G1
- [x] `gateway/app/main.py`: FastAPI catch-all route that proxies to `BANK_URL` with httpx, adds `X-Request-Id`, emits an event for every request
- [x] Rule engine: load `rules:active` from Redis at start; evaluate path rules, then regex/header rules (decision order in design doc section 7)
- [x] DENY response shape + `X-Verdict` header exactly as in the contract
- [x] Rule packs: `gateway/rules/packs/sqli.yaml`, `prompt.yaml`, `logi.yaml` (all `owasp: A05`), at least 5 rules each, based on the OWASP testing guide
- [x] `tests/corpus/corpus.jsonl`: first 40 items (20 benign, 20 malicious across A05), each with `expected_verdict`
- [x] `gateway/tests/test_rules.py`: every pack rule has a corpus item that hits it, and no benign item is DENYed

### P2 — DIVERT path (H6–12) · due at G2
- [ ] Rate rules with Redis counters: login burst (A07), transfer burst (A06), keyed by IP or account
- [ ] Path rules: `/admin` and `/debug` (A02); account id ≠ session owner (A01); statement fetch to an internal host (A01)
- [ ] Anomaly score v1: weighted sum of length vs route baseline, special-character ratio, unseen path, unseen param names → 0..1
- [ ] DIVERT handling: forward to `HONEYPOT_URL` and return its response; fire-and-forget `POST SANDBOX_URL/replay`
- [ ] `sandbox/app/main.py`: `/replay` → call `BANK_SANDBOX_URL`, record status, error and latency, emit event
- [ ] Corpus: add items for A01, A02, A06, A07, A10 (both benign look-alikes and malicious)

### P3 — Learning loop (H12–18) · due at G3
- [ ] Subscribe to `rules:updated`; reload rules in under 1 s with no restart
- [ ] Anomaly score v2: tune weights on the corpus so all benign items stay below `DIVERT_THRESHOLD`
- [ ] Sandbox: set `stack_trace_leaked=true` when the 500 body looks like a Python traceback (A10)
- [ ] Gateway p95 verdict time under 5 ms on cached rules. Add a tiny benchmark script in `gateway/bench.py`.

### P4 — Demo hardening (H18–22) · due at G4 (feature freeze)
- [ ] `tests/corpus/scenarios/full.yaml`: steps in the order of `docs/07-demo-script.md`
- [ ] Step 5 corpus: one A06 pattern that no rule covers yet (it must DIVERT on first sight), plus 3 similar variants for after learning
- [ ] Run the full scenario 3 times; fix any SAFE item that trips DIVERT
- [ ] Prepare your speaking part: steps 2–4 of the demo

---

## Interfaces you depend on

| From | What | Where |
|---|---|---|
| Jerush | `shared/schemas.py` (`Event`, `Rule`), `shared/events.emit` | design doc sections 4–6 |
| Jerush | Rules arrive in Redis `rules:active` (the analyst loads your pack YAML) | section 6 |
| Akchhat | Bank routes and response shapes | section 8 bank table |

## Requests to Jerush / Akchhat

_Write requests here (date, what, why). The owner makes the change._

-
