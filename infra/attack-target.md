# Public gateway for OWASP attack tests (homelab)

**What is public:** only the gateway, at `https://attack.jrushvj.dev`, behind a Cloudflare Access login.
**What is not:** the bank, honeypot, sandbox, analyst, redis, postgres, dashboard. They stay on the internal Docker
network. The gateway port is bound to `127.0.0.1` on the homelab, so only the local tunnel connector can reach it.

Attack traffic path:

```
tester (internet) → https://attack.jrushvj.dev → Cloudflare Access (login) → tunnel → gateway :8000
                   → verdict: DENY (403) | DIVERT (honeypot + sandbox, learner) | SAFE (VulnBank)
```

---

## Part 1: Homelab stack (run on the homelab, as your own user)

1. Get the code (the `main` branch with the public-gateway change):
   ```bash
   git clone https://github.com/Hackfest-X-Saividya/hackstreet-boys-t2-08.git ~/sphere
   cd ~/sphere
   git checkout main && git pull
   ```
2. Create `.env` from the example and set the values that matter:
   ```bash
   cp .env.example .env
   ```
   Edit `.env`:
   - `ADMIN_TOKEN=<long random string>` (protects the reset button; generate one, don't reuse `dev-admin-token`)
   - `LLM_MODE=kaggle`, `DEFENSE_LLM_URL=<trycloudflare URL from the Kaggle notebook>`, `DEFENSE_LLM_KEY=<its key>`
     (or `LLM_MODE=mock` / `DEMO_OFFLINE=1` if Kaggle is off; the attacks still run)
3. Start the production stack (no dev override, so only gateway and dashboard publish ports):
   ```bash
   docker compose -f docker-compose.yml up --build -d
   docker compose -f docker-compose.yml ps        # every service must say (healthy)
   curl -s http://127.0.0.1:8000/health            # {"status":"ok"}
   ```

## Part 2: Cloudflare tunnel for the gateway (in your Cloudflare dashboard)

1. Cloudflare → **Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel** → type **Cloudflared**.
   Name it `sphere-attack` → **Save tunnel**.
2. Choose the OS of the homelab. The screen shows an install command with a long token (`eyJ…`).
   Copy **only the token**. Keep it secret: anyone with it can run your tunnel.
3. On the homelab, install the connector as a service (Linux example; Windows uses `cloudflared.exe service install <token>` in an admin prompt):
   ```bash
   sudo cloudflared service install <TOKEN>
   ```
   Back in the dashboard, the connector shows **Connected** within about 30 seconds. Click **Next**.
4. **Public hostname** tab → **Add a public hostname**:
   - Subdomain: `attack`
   - Domain: `jrushvj.dev`
   - Service: type **HTTP**, URL **`localhost:8000`** (the gateway, nothing else)
   - **Save**. This creates the DNS record and the HTTPS endpoint.
   Add **no other** public hostnames to this tunnel.
5. Check from outside the homelab (any machine, it should still ask for login, which is correct):
   ```bash
   curl -I https://attack.jrushvj.dev/health
   ```
   You should get a redirect to `*.cloudflareaccess.com` (the Access login), not a bank page.

## Part 3: Cloudflare Access (who may attack)

1. Zero Trust → **Access** → **Applications** → **Add an application** → **Self-hosted**.
   - Application name: `sphere-attack`
   - Domain: `attack.jrushvj.dev`
   - Session duration: 1 hour is fine for a demo.
2. Add a policy **Allow**, **Include**: the emails of your named testers only (for example `abhinav…@gmail.com`).
3. For automated runs from your laptop, add a **service token** so the runner can get past Access without a login:
   - Zero Trust → **Access** → **Service Auth** → **Create service token** → name `attack-runner`.
   - Add a second policy on the same application: action **Service Auth**, include the `attack-runner` token.
   - Copy the **Client ID** and **Client Secret** once (the secret is shown only once).

Testers who use a browser log in with their email. The corpus runner uses the service token.

## Part 4: Connect VulnBank (Abhinav's UI)

Nothing extra to set up. VulnBank is reached through the gateway like any request, so its pages are at:

| Page | URL |
|---|---|
| Login | `https://attack.jrushvj.dev/login` |
| Accounts | `https://attack.jrushvj.dev/accounts` |
| Search (SQLi) | `https://attack.jrushvj.dev/search` |
| Transfer (A06) | `https://attack.jrushvj.dev/transfer` |
| Support chat (prompt injection) | `https://attack.jrushvj.dev/support` |
| Statements URL (A01 SSRF) | `https://attack.jrushvj.dev/statements` |

Seed logins: `customer<N>@example.test` / `password123`.

Browser testers: open the login page, sign in with the Access email, then the VulnBank login.

## Part 5: Launch the OWASP corpus attacks

Run from your laptop (needs the repo and Python with `httpx`). Use the service token from Part 3:

```cmd
set CF_ACCESS_CLIENT_ID=<client id>
set CF_ACCESS_CLIENT_SECRET=<client secret>
python tests/e2e/attack_corpus.py --base https://attack.jrushvj.dev --allow-host attack.jrushvj.dev > attack_run_1.txt
```

It sends only malicious corpus items and prints each verdict, marks any that differ from the expected verdict, and prints a
summary per OWASP category. Save the output for the slides.

**Before a clean run**, reset the demo on the homelab (learned rules and counters from earlier runs change the results).
The analyst port is not public, so run the reset inside the stack:

```bash
cd ~/sphere
docker compose -f docker-compose.yml exec analyst python -c "import httpx,os; print(httpx.post('http://127.0.0.1:8004/api/hp/reset', headers={'X-Admin-Token': os.environ['ADMIN_TOKEN']}).status_code)"
```

It should print `200`. (`os.environ['ADMIN_TOKEN']` is read from `.env` only if the analyst container has it: check with
`docker compose -f docker-compose.yml exec analyst printenv ADMIN_TOKEN`.)

## What to expect (and what not to expect)

- **Known patterns are DENY (403)** immediately: SQL tautologies, prompt "ignore instructions", forged log lines.
- **Unknown-looking patterns are DIVERT (200 from a decoy)**: the honeypot answers with fake data, the sandbox replays the
  request against a throwaway bank, and the analyst may learn a rule. The next similar request is DENY.
- **Some attacks pass as SAFE** and reach the real VulnBank. Examples: login attempts before a burst threshold, and any
  attack no rule covers (A03, A04, A08, A09 have no detection). Those results are the honest coverage gaps.
- Rate limits are per **real client IP** (from `CF-Connecting-IP`), so each tester has their own counter.

## Safety checks before you open it

- [ ] `docker compose -f docker-compose.yml ps` shows only the gateway (127.0.0.1:8000) and the dashboard as published ports
- [ ] `curl -I https://attack.jrushvj.dev/health` redirects to the Access login
- [ ] The tunnel has exactly one public hostname (`attack` → `localhost:8000`)
- [ ] `ADMIN_TOKEN` is a new random value
- [ ] The bank database resets (`docker compose down -v` then `up`) between sessions: a SAFE destructive query really runs against it
- [ ] You stop the tunnel when the session ends: `sudo systemctl stop cloudflared` (or `sudo cloudflared service uninstall`)
