# 07 — Demo script

One button, **Run scenario**, on the dashboard plays `tests/corpus/scenarios/full.yaml`
in this order. Times are targets. Speaker in brackets.

| Step | Time | What judges see | OWASP tile | Speaker |
|---|---|---|---|---|
| 1. Normal traffic | 20 s | Customers log in and check balances, all green SAFE | — | Akchhat |
| 2. Rule packs | 40 s | Search, chat and memo attempts → instant red DENY | A05 | Abhinav |
| 3. Access + config | 40 s | Another customer's account, open admin panel, internal statement URL → DENY | A01, A02 | Abhinav |
| 4. Login burst | 20 s | Failed logins → DENY after threshold | A07 | Abhinav |
| 5. Zero-day moment | 60 s | New transfer-abuse pattern → amber DIVERT → rule appears → next one red DENY; timer shows seconds | A06 | Jerush |
| 6. Error handling | 20 s | Malformed input → stack-trace leak spotted in sandbox → DIVERT | A10 | Jerush |
| 7. Wrap-up | 20 s | Scoreboard: 7 live, 3 on slide (A03, A04, A08 clips); our dashboard is the A09 fix | A09 | Jerush |

Total: about 3 min 40 s. If short on time, skip step 6.

## Fallbacks (in order)

1. Kaggle or tunnel down → set `LLM_MODE=local` (RTX 4060) and restart `analyst`.
2. Local model fails → `DEMO_OFFLINE=1` (canned rules; the flow looks identical).
3. Venue Wi-Fi blocks Cloudflare → phone hotspot for the homelab, or run on Jerush's laptop in offline mode.
4. Everything fails → play the recorded fallback video (made at G4).

## Checklist before going on stage

- [ ] Homelab on `demo-ready` tag, all containers healthy
- [ ] `demo.jrushvj.dev` loads behind Cloudflare Access
- [ ] DB reset: `docker compose exec analyst python -m analyst.reset_demo`
- [ ] Fallback video on the presenting laptop's desktop
- [ ] Slides open on the A03 / A04 / A08 clip slide
