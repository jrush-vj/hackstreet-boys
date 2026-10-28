# gateway/ — owner: Abhinav

Reverse proxy on port 8000. Gives every request a SAFE / DIVERT / DENY verdict.

- Contract: `docs/04-system-design.md` sections 5–8
- Rule packs: `rules/packs/*.yaml` (format in design doc section 6). The analyst loads them into Redis; the gateway reads only from Redis.
- At startup, the gateway loads the enabled rules in Redis `rules:active`. Every `rules:updated` notification, whether it contains a rule ID or `*`, triggers a complete reload of that hash.
- Decision order is path rules, Redis-backed rate rules, regex/header rules, then the anomaly score. A matching DENY takes precedence over DIVERT. The A07 login counter is keyed by client IP; the A06 transfer counter is keyed by source account.
- `/admin`, `/debug`, and statement fetches addressed to known internal hosts are DENYed. Successful login responses associate a hashed bearer token with its customer ID in Redis so account responses for another customer are DENYed without returning the bank response.
- DIVERT requests are forwarded to the honeypot; a background replay is posted to the sandbox with the same correlation ID. All responses include `X-Request-Id` and `X-Verdict`, and each request emits a gateway event with its anomaly score.
- Anomaly scoring weights request length (0.25), special-character ratio (0.30), unseen paths (0.15), and unseen parameter names (0.30); corpus tests keep every benign sample below `DIVERT_THRESHOLD`. Hashed session-owner keys expire after one hour.
- Run `docker compose run --rm gateway python bench.py` to measure cached in-process verdict p95; the benchmark fails if it reaches 5 ms.
- Layout: `app/main.py`, `app/engine.py`, `app/anomaly.py`, `tests/`, `bench.py`, `requirements.txt`, `Dockerfile`
- Tasks: `team/ABHINAV.md`
