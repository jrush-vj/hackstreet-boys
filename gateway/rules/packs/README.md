# Rule packs (predefined groups)

Three groups, one file each. Every rule is A05 (injection), and the rule id says which group it belongs to.

| File | Group | Known patterns (`…-0xx`, DENY) | Unknown-looking variants (`…-100`, DIVERT) |
|---|---|---|---|
| `sqli.yaml` | SQL injection | tautologies, UNION, stacked statements, schema enumeration, time-based | a quote or comment next to a SQL keyword |
| `prompt.yaml` | Prompt injection | "ignore previous instructions", persona/developer-mode, role markers | instruction-override wording |
| `logi.yaml` | Log injection | forged log lines via %0a/%0d, ANSI, NUL, log4j lookups | control characters or NUL in any field |

- **DENY** blocks at the gateway (403) and is counted on the dashboard.
- **DIVERT** sends the request to the honeypot and the sandbox. The analyst studies it and may learn a specific
  `L-…` DENY rule, so the next variant is blocked. DENY always wins over DIVERT.
- Other files here: `access.yaml` (A01/A02), `rate.yaml` (A06/A07), `canary.yaml` (honeypot canaries).

Every rule needs at least one labelled item in `tests/corpus/corpus.jsonl`. `gateway/tests/test_predefined.py`
checks that, plus the expected verdict of every new item.
