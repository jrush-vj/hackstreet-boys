# sandbox/ — owner: Abhinav

Port 8003, internal only. `POST /replay` replays a DIVERTed request against `bank-sandbox`
(a throwaway bank with a fresh DB) and emits a `source="sandbox"` event.

- Contract: `docs/04-system-design.md` section 8 (sandbox)
- Replay bodies use `body_b64`; responses are accepted with `202`. The sandbox records the bank-sandbox status (or `0` on connection failure), error, latency in milliseconds, and the shared correlation ID in its event.
- Tasks: `team/ABHINAV.md`
