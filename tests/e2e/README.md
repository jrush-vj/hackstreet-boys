# tests/e2e/ — owner: Jerush

`test_g1.py`, `test_g2.py`, `test_g3.py`: one per gate, run against a full `docker compose up`.
Criteria: `docs/05-phases-and-gates.md`.

Run from the repo root with the dev stack up (`docker compose up --build -d`):

```bash
pip install -r tests/e2e/requirements.txt
pytest tests/e2e -q
```

`test_g0.py` checks every container is healthy and every contract endpoint answers.
