# Homelab deploy (Lenovo LOQ) — Jerush only

The homelab runs **tagged builds only**, with the production compose file (no dev override, so only
gateway :8000 and dashboard :3000 are published, and the bank network stays internet-free).

## One-time setup

1. Install Docker Engine + Compose plugin, git, and `cloudflared`.
2. `git clone https://github.com/Hackfest-X-Saividya/hackstreet-boys-t2-08.git ~/sphere && cd ~/sphere`
3. `cp .env.example .env`, then edit `.env`:
   - `LLM_MODE=kaggle`, `DEFENSE_LLM_URL=https://defense.jrushvj.dev`, `DEFENSE_LLM_KEY=<key from the Kaggle notebook>`
   - leave everything else as in `.env.example`
4. Cloudflare tunnel for the dashboard (token stays on this machine, never in git):
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create sphere-demo
   cloudflared tunnel route dns sphere-demo demo.jrushvj.dev
   ```
   `~/.cloudflared/config.yml`:
   ```yaml
   tunnel: sphere-demo
   credentials-file: /home/<you>/.cloudflared/<tunnel-id>.json
   ingress:
     - hostname: demo.jrushvj.dev
       service: http://localhost:3000     # dashboard ONLY. Never add the gateway, bank or honeypot.
     - service: http_status:404
   ```
   Then `sudo cloudflared service install`.
5. Cloudflare dashboard → Zero Trust → Access → Applications: add `demo.jrushvj.dev`,
   policy "Allow" for the three team emails only.

## Deploy a tag

```bash
cd ~/sphere
git fetch --tags origin
git checkout <tag>                 # e.g. g1-core, g2-divert, demo-ready
docker compose -f docker-compose.yml down
docker compose -f docker-compose.yml up --build -d
docker compose -f docker-compose.yml ps     # every service (healthy)
curl -s localhost:3000/health && curl -s localhost:8000/health
```

`-f docker-compose.yml` matters: it skips `docker-compose.override.yml`, so internal services get no host ports.

## LLM modes

| Mode | `.env` | When |
|---|---|---|
| `kaggle` | `DEFENSE_LLM_URL=https://defense.jrushvj.dev` + key | Normal demo (`kaggle/defense.ipynb` running) |
| `local` | `LLM_MODE=local`, `LOCAL_LLM_URL=http://host.docker.internal:8080` | Kaggle or tunnel down |
| offline | `DEMO_OFFLINE=1` | Local model fails too (canned rules) |

Local fallback model on the RTX 4060 (outside Docker, port 8080):
```bash
llama-server -m ~/models/qwen2.5-7b-instruct-q4_k_m.gguf --host 0.0.0.0 --port 8080 -ngl 99 -c 4096
```
`docker-compose.yml` maps `host.docker.internal` to the host for the analyst, so this also works on Linux.

After changing `.env`: `docker compose -f docker-compose.yml up -d analyst`.

## Before going on stage

See the checklist in `docs/07-demo-script.md`.
