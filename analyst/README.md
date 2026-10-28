# analyst/ — owner: Jerush

Port 8004. Consumes the Redis `events` stream, persists to Postgres, turns DIVERTs into
validated rules via the defense LLM, and serves the dashboard API + WebSocket.

- Contract: `docs/04-system-design.md` sections 6, 8 (analyst), 9, 11
- `LLM_MODE`: `mock` (mock-llm) | `kaggle` (`defense.jrushvj.dev`) | `local` (llama.cpp on homelab GPU)
- Tasks: `team/JERUSH.md`
