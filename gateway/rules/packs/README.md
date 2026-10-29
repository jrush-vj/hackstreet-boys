# Rule packs (predefined groups)

Three groups, one file each. Every rule is A05 (injection), and the rule id says which group it belongs to.

| File | Group | Patterns (`…-0xx` and `…-100`, DIVERT on first run) | Learned after the first run |
|---|---|---|---|
| `sqli.yaml` | SQL injection | tautologies, UNION, stacked statements, schema enumeration, time-based | a quote or comment next to a SQL keyword |
| `prompt.yaml` | Prompt injection | "ignore previous instructions", persona/developer-mode, role markers | instruction-override wording |
| `logi.yaml` | Log injection | forged log lines via %0a/%0d, ANSI, NUL, log4j lookups | control characters or NUL in any field |

- The injection groups are **unknown on first run**: every match is DIVERT. The learner then adds an `L-…` DENY rule, so the next identical attack is DENY.
- **DIVERT** sends the request to the honeypot and the sandbox. DENY always wins over DIVERT.
- Other files here: `access.yaml` (A01/A02), `rate.yaml` (A06/A07), `canary.yaml` (honeypot canaries).

Every rule needs at least one labelled item in `tests/corpus/corpus.jsonl`. `gateway/tests/test_predefined.py`
checks that, plus the expected verdict of every new item.
