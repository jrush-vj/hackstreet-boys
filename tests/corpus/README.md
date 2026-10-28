# tests/corpus/ — owner: Abhinav

- `corpus.jsonl`: labelled requests (format in `docs/04-system-design.md` section 10)
- `scenarios/full.yaml`: the demo order from `docs/07-demo-script.md`
- The A06 variants marked `expected_after_learning` are expected to DENY only after the step-5 first-sight request creates its learned rule.
Malicious items come only from public, documented test cases (OWASP WSTG, ZAP rule docs).
