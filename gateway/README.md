# gateway/ — owner: Abhinav

Reverse proxy on port 8000. Gives every request a SAFE / DIVERT / DENY verdict.

- Contract: `docs/04-system-design.md` sections 5–8
- Rule packs: `rules/packs/*.yaml` (format in design doc section 6). The analyst loads them into Redis; the gateway reads only from Redis.
- Layout: `app/main.py`, `app/engine.py`, `app/anomaly.py`, `tests/`, `bench.py`, `requirements.txt`, `Dockerfile`
- Tasks: `team/ABHINAV.md`
