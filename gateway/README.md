# gateway/ — owner: Abhinav

Reverse proxy on port 8000. Gives every request a SAFE / DIVERT / DENY verdict.

- Contract: `docs/04-system-design.md` sections 5–8
- Rule packs: `rules/packs/*.yaml` (format in design doc section 6). The analyst loads them into Redis; the gateway reads only from Redis.
- At startup, the gateway loads the enabled rules in Redis `rules:active`. Every `rules:updated` notification, whether it contains a rule ID or `*`, triggers a complete reload of that hash.
- Decision order is path rules followed by regex/header rules; a matching DENY takes precedence over DIVERT. All responses include `X-Request-Id` and `X-Verdict`, and each request emits a gateway event.
- Layout: `app/main.py`, `app/engine.py`, `app/anomaly.py`, `tests/`, `bench.py`, `requirements.txt`, `Dockerfile`
- Tasks: `team/ABHINAV.md`
