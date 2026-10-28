# Exposing the lab for outside attack tests (decision needed first)

**Decision:** AGENTS.md section 7 says the gateway, bank and honeypot must never be tunnelled. Putting the gateway
on a public URL changes that rule. Do this only after you change the rule yourself (AGENTS.md is yours to edit).

## Option A (recommended): gateway on a named tunnel behind Cloudflare Access
Only the gateway is published; the bank, honeypot, sandbox and analyst stay on the internal Docker network.

1. Cloudflare dashboard → Zero Trust → Networks → Tunnels → create `sphere-attack` (same steps as `infra/homelab.md`).
2. Public hostname: `attack.jrushvj.dev` → `http://localhost:8000` (gateway only).
3. Zero Trust → Access → Applications: add `attack.jrushvj.dev`, policy **Allow** for the named testers' emails only.
   Cloudflare terminates HTTPS on the domain, so the tester connects over `https://attack.jrushvj.dev`.
4. Deploy as in `infra/homelab.md` (tagged build, `docker-compose.yml` without the override).

## Without root on the server
Testers get HTTP access through the tunnel only. They never get a shell, Docker access or the `.env` file.
Docker itself is root-equivalent on the host, so the host account that runs the stack must be yours alone.

## What testers may send
Only the labelled corpus (`tests/corpus/corpus.jsonl`), per AGENTS.md section 7. The runner's allowlist
(`tests/e2e/run_samples.py`) accepts localhost and gateway:8000 only. Remote use needs a deliberate, explicit
flag and a host list. I have not added that yet.

## Before the test
- [ ] Rule in AGENTS.md section 7 amended by you for the gateway
- [ ] Access policy lists only named testers
- [ ] `.env` has a fresh `DEFENSE_LLM_KEY`; the bank has no internet route (unchanged)
