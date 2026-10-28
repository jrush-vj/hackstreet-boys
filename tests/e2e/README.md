# tests/e2e/ — owner: Jerush

One file per gate, run against a full dev `docker compose up` (criteria: `docs/05-phases-and-gates.md`).

| File | Gate | Checks |
|---|---|---|
| `test_g0.py` | G0 | every container healthy, every contract endpoint answers |
| `test_g1.py` | G1 | benign SAFE requests reach the real bank (< 400), the 3 A05 packs DENY, events persisted, stats count |
| `test_g2.py` | G2 | a DIVERT links gateway + honeypot + sandbox events by `correlation_id`; A01/A02/A07 corpus verdicts; live feed over `/ws/live` via nginx |

`conftest.py` clears Redis `rate:*` counters before each test, so reruns don't trip rate limits.

Run from the repo root with the dev stack up (`docker compose up --build -d`):

```bash
pip install -r tests/e2e/requirements.txt
pytest tests/e2e -q
```
