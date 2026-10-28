# Abhinav — detection: gateway, sandbox, corpus

You own the brain of the defense: the gateway that gives every request a verdict, the
sandbox that replays suspicious ones safely, and the labelled test corpus.

**Your folders (edit only these):** `gateway/`, `sandbox/`, `tests/corpus/`
**Read first:** `AGENTS.md`, `docs/04-system-design.md` sections 2, 5–8 and 10

---

## Updates from Jerush (read these first, newest at the top)

### ▶ CURRENT: read this first (updated 2026-10-29, after G3)

State: `main` has everyone's P1 + P2 + P3 and is tagged `g3-learning`. 30/30 e2e pass (G0–G3 + honeypot console).

**Standing rules (every session, your coding agent does these without being told):**
- Session start: `git checkout feat/abhinav-p1-gateway && git fetch origin && git merge origin/main` (merge, never rebase or force-push).
- Work only in `gateway/`, `sandbox/`, `tests/corpus/`. Save files as UTF-8.
- Bank request bodies: follow the table in `docs/04-system-design.md` section 8. If you change one, note it under "Requests to Jerush / Akchhat".
- Before saying a task is done: `docker compose up --build -d`, your service tests, and `pytest tests/e2e -q` (all must pass, except tests that are red only because they wait for a later phase).
- **When a step is done:** tick it here, commit only your folders and this file, push to `feat/abhinav-p1-gateway`, and add one line
  `READY TO MERGE (<date>): <what>` under "Requests to Jerush" below. Jerush checks this file and merges. Nobody needs to message anyone.

**Jerush changed in your folders (P3 integration, merge `origin/main` before touching these):**
- `gateway/app/main.py` is **unchanged from your version**. Bans are display-only in the honeypot console (Jerush's
  decision: the gateway never blocks an IP). `gateway/rules/packs/canary.yaml` adds `canary-001`: a reused honeypot canary key
  (`vb_live_CANARY_<12 hex>`) is DENYed like any other rule hit.
- `gateway/tests/test_proxy.py`: `FakeRedis` got `sismember`/`sadd`/`hset`, plus `test_canary_reuse_is_denied_but_never_bans_the_ip`.
- The analyst now learns a rule from every DIVERT (P3). A learned `L-xxxxxxxx` rule reaches your gateway through `rules:updated`
  (measured: the next similar request is DENYed about 1 s after first sight). `tests/e2e/conftest.py` resets the demo before each test.
- The bank now leaks a real Python traceback with a 500 on `GET /api/accounts/<non-number>`, so your sandbox
  `stack_trace_leaked` check has something to catch. Use that path (GET) for the A10 step in `scenarios/full.yaml`.

**Do now, in order (P4, due at G4 = feature freeze):**
1. [ ] Merge `origin/main` (standing rules), then `docker compose down -v && docker compose up --build -d`,
       `docker compose run --rm gateway pytest -q` and `pytest tests/e2e -q`: **30 pass** (G0–G3 + honeypot console).
2. [ ] Step-5 corpus (the zero-day moment): one **new** A06 transfer-abuse item that no rule covers (it must DIVERT on first
       sight), plus 3 variants that the learned rule must DENY. In offline mode the learned rule is the canned A06 one
       (`shared/canned.py`: a JSON field holding 8+ punctuation characters), so make the variants fit it too.
3. [ ] `tests/corpus/scenarios/full.yaml`: `[{step, corpus_ids, delay_ms}]` in the order of `docs/07-demo-script.md`.
       Step 5 = first-sight item, then `delay_ms: 3000` (learning takes ~1 s with mock, longer with Kaggle), then the 3 variants.
       Step 6 (A10) = a GET to `/api/accounts/<not-a-number>?…` that DIVERTs, so the sandbox catches the leaked stack trace.
4. [ ] Run the full scenario 3 times (Jerush's runner, or by hand), and fix any benign item that trips DIVERT.
5. [ ] Prepare your speaking part: steps 2–4 of the demo.

### History (all done, kept for reference: what Jerush changed in your files and why)

#### 2026-10-28 — P2 integration (G2 green locally) — done
Your P2 (rate + path rules, owner check, anomaly v1, DIVERT → honeypot + sandbox) works end to end. Thanks!

**Jerush changed in your folders** (merge `origin/main` before you touch these files):
- `tests/corpus/corpus.jsonl`: added `c-0056`…`c-0061`, an A07 login burst (OWASP WSTG-ATHN-03) with wrong passwords.
  G2 needed A07 **DENY** items. With `c-0054` counted first, attempts 1–4 are SAFE and 5–6 are DENY (limit 5/min per IP).
- `gateway/tests/test_rules.py`: `test_p2_corpus_items_match_their_labels` now keeps one fake Redis **per OWASP category**,
  the same way the e2e tests count. Before, the earlier benign login counted toward the burst.
- `tests/e2e/conftest.py` (Jerush's) clears `rate:*` before every e2e test, so reruns inside 60 s don't trip the limits.
- `docs/04-system-design.md` section 7 now documents your response-side A01 check (`access-account-owner`).

**Your next steps (P3, due at G3):**
1. [x] `git fetch origin && git merge origin/main`, then rebuild and run `pytest tests/e2e -q` (22 must pass).
2. [x] Hot reload on `rules:updated` under 1 s. You already reload; add a test that times it.
3. [x] Anomaly score v2: tune on the corpus so every benign item stays below `DIVERT_THRESHOLD`.
4. [x] Sandbox: set `stack_trace_leaked=true` when the replayed 500 body looks like a Python traceback (A10).
5. [x] `gateway/bench.py`: p95 verdict time under 5 ms on cached rules.
6. [x] Optional: give `session-owner:*` keys a TTL (for example 1 h), so they don't pile up in Redis.

#### 2026-10-28 — G2 test is ready (`tests/e2e/test_g2.py`) — done
It's red until your P2 lands. It expects:
- [x] At least one corpus item with `"expected_verdict": "DIVERT"`. Sending it must give `X-Verdict: DIVERT`, and within 8 s the analyst must have
      **gateway + honeypot + sandbox** events with that request's `X-Request-Id` as `correlation_id`.
      Sandbox `details` must have `status`, `error`, `latency_ms`, `stack_trace_leaked`.
- [x] Corpus items for `A01`, `A02` and `A07`, each with at least one `expected_verdict: "DENY"`. They're sent **in file order**,
      and each response's `X-Verdict` must equal its `expected_verdict`. So for the A07 login burst, list the attempts
      in order: SAFE up to the limit, then DENY. The test clears Redis `rate:*` keys before each case.
- The bank request bodies table in `docs/04-system-design.md` section 8 still applies to every new item.

#### 2026-10-28 — P1 integration (G1 green, on `main`, tagged `g1-core`) — done

**Your next steps, in order:**
1. [x] Get the integrated code: `git checkout feat/abhinav-p1-gateway && git fetch origin && git merge origin/main`
       (this brings in Jerush's corpus fixes; take `main`'s version if anything conflicts).
2. [x] Check it runs: `docker compose down -v && docker compose up --build -d`, then
       `docker compose run --rm gateway pytest -q` and `pytest tests/e2e -q` (G0 + G1 must stay green).
3. [x] Start **P2** (Part 2 below, due at G2): rate rules (A07 login burst, A06 transfer burst), path rules (A01, A02),
       anomaly score v1, DIVERT → honeypot + fire-and-forget `POST /replay`, the real `sandbox/`, corpus items for A01/A02/A06/A07/A10.
4. [x] Push to your branch whenever a piece works, and tell Jerush "ready to merge". G2 checks that a DIVERT produces
       gateway + honeypot + sandbox events with the same `correlation_id`, and that A01, A02 and A07 DENY.
   - When you DIVERT, forward the request to the honeypot **with the same `X-Request-Id` header**; the honeypot copies it into `correlation_id`.

**New git workflow** (full version: `AGENTS.md` section 6, `docs/06-git-workflow.md`):
- You keep **one branch for the whole event**: `feat/abhinav-p1-gateway`. Don't create others.
- Start every session with `git fetch origin && git merge origin/main`.
- When a task is done: commit only your folders, push to your branch, and tell Jerush "ready to merge".
- **Never rebase or force-push.** Jerush merges your branch, so its history must not change.
- Only Jerush pushes to `main`. You don't open PRs.

**What happened to your P1 work:** merged into `feat/jerush-analyst-core`, then pushed to `main`.
G1 passes. Your gateway tests pass 5/5. The `DeprecationWarning` comes from Starlette itself and is harmless.

**Jerush changed in your folders** (merge `origin/main` before you touch these files):
- `tests/corpus/corpus.jsonl`: the bank rejected 3 SAFE items with 422 because their bodies didn't match the bank.
  - `c-0002`, `c-0016` (login) now send `{"email": "customer1@example.test" / "customer2@...", "password": "password123"}`
  - `c-0011` (transfer) now sends `{"from_account_id": 3, "to_account_id": 18, "amount": 25.0}`

**Do this from now on:**
- [x] Use the bank request bodies in `docs/04-system-design.md` section 8 (new table) for every corpus item,
      especially the P2 login-burst (A07) and transfer-burst (A06) items. Seed logins: `customer<N>@example.test` / `password123`.
- [x] `tests/e2e/test_g1.py` now also requires every SAFE item to return a status below 400, not just `X-Verdict: SAFE`.
- [x] `rules:updated` can carry a rule id or `*`, and `rules:active` holds enabled rules only. Your gateway already handles both.

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
- [x] Rate rules with Redis counters: login burst (A07), transfer burst (A06), keyed by IP or account
- [x] Path rules: `/admin` and `/debug` (A02); account id ≠ session owner (A01); statement fetch to an internal host (A01)
- [x] Anomaly score v1: weighted sum of length vs route baseline, special-character ratio, unseen path, unseen param names → 0..1
- [x] DIVERT handling: forward to `HONEYPOT_URL` and return its response; fire-and-forget `POST SANDBOX_URL/replay`
- [x] `sandbox/app/main.py`: `/replay` → call `BANK_SANDBOX_URL`, record status, error and latency, emit event
- [x] Corpus: add items for A01, A02, A06, A07, A10 (both benign look-alikes and malicious)

### P3 — Learning loop (H12–18) · due at G3
- [x] Subscribe to `rules:updated`; reload rules in under 1 s with no restart (verified ~0.46 s)
- [x] Anomaly score v2: tune weights on the corpus so all benign items stay below `DIVERT_THRESHOLD`
- [x] Sandbox: set `stack_trace_leaked=true` when the 500 body looks like a Python traceback (A10)
- [x] Gateway p95 verdict time under 5 ms on cached rules. Add a tiny benchmark script in `gateway/bench.py`.

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

- READY TO MERGE (2026-10-28): P3 anomaly v2, traceback leak detection, cached-rule benchmark, and session-owner TTL completed; gateway 10, sandbox 4, and e2e 22 tests pass.
