# 03 — Hardware and environments

## Machines and roles

| Machine | Used by | Role | Access |
|---|---|---|---|
| Abhinav's laptop | Abhinav | Dev: gateway, sandbox, corpus | GitHub repo only |
| Akchhat's laptop | Akchhat | Dev: bank, honeypot, dashboard | GitHub repo only |
| Jerush's laptop (Claude Code) | Jerush | Integration: merges, end-to-end tests, builds, release tags | Everything |
| Homelab: Lenovo LOQ (i7-13650HX, 24 GB RAM, RTX 4060 8 GB) | Jerush only | Staging + demo host; local fallback LLM on GPU | Jerush only |
| Kaggle account #1 (T4 16 GB) | Jerush only | Optional traffic-variant generator for the runner | Jerush only |
| Kaggle account #2 (T4 16 GB) | Jerush only | Defense LLM (OpenAI-compatible server) | Jerush only |
| Cloudflare (jrushvj.dev) | Jerush only | Tunnels + Cloudflare Access | Jerush only |

Teammates never need homelab, Kaggle or Cloudflare access. Mock mode covers it.

## Environments

| Env | Where | `LLM_MODE` | Who | Purpose |
|---|---|---|---|---|
| dev | Each laptop | `mock` | Everyone | Build and unit-test own services |
| integration | Jerush's laptop | `mock`, then `kaggle` | Jerush | Merge, run `tests/e2e/`, catch contract breaks |
| staging / demo | Homelab LOQ | `kaggle` (fallback `local`) | Jerush | Run the tagged build for judges |

## Network layout (demo)

```
Internet ──► Cloudflare ──► demo.jrushvj.dev     ──► homelab: dashboard :3000 (behind Cloudflare Access)
                        Kaggle #2 LLM server ◄── https://<random>.trycloudflare.com quick tunnel (API key required)

homelab Docker:
  net "edge"     : gateway, dashboard, analyst, runner, mock-llm
  net "internal" : gateway, analyst, bank, bank-sandbox, honeypot, sandbox, redis, postgres   (internal: true)
```

- Only the dashboard is exposed through Cloudflare. **Never** tunnel the gateway, bank or honeypot.
- The bank network is `internal: true`, so the deliberately weak app can't reach the internet.
- `analyst` (on `edge`) is the only service that calls out to the Kaggle LLM (`DEFENSE_LLM_URL`, a `*.trycloudflare.com` URL that changes every Kaggle run).

## Memory budget (homelab, demo mode)

| Service | Limit |
|---|---|
| gateway, sandbox, analyst, runner | 512 MB each |
| bank, bank-sandbox, honeypot | 256 MB each |
| dashboard | 256 MB |
| redis | 256 MB |
| postgres | 512 MB |
| local fallback LLM (llama.cpp, GPU) | runs on the host or in its own container, ~6 GB VRAM |

## Laptop requirements for teammates

- 8 GB RAM minimum (16 GB is comfortable), 15 GB free disk
- Windows 10/11 with WSL2, or macOS 13+
- Setup steps: see your `team/<NAME>.md`
