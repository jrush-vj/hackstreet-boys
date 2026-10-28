"""Predefined groups + unknown variants, end to end through the gateway.
Known SQL/prompt/log patterns are DENYed by their group. An unknown SQL variant is DIVERTed (honeypot + sandbox
study it), the analyst learns a rule, and the next variant is DENYed by that learned rule."""

import time

import httpx

from test_g1 import ANALYST, GATEWAY, corpus, send

ADMIN = {"X-Admin-Token": "dev-admin-token"}


def test_known_groups_deny_with_their_rule_group():
    for name, prefix in [("c-0067", "sqli-"), ("c-0083", "prompt-"), ("c-0069", "sqli-")]:
        item = next(c for c in corpus() if c["id"] == name)
        r = send(item)
        assert r.status_code == 403 and r.json()["rule_id"].startswith(prefix), (name, r.text)
    rules = {r["id"]: r for r in httpx.get(f"{ANALYST}/api/hp/rules").json()}
    assert rules["sqli-012"]["category"].startswith("SQL injection")
    assert rules["prompt-011"]["category"].startswith("Prompt injection")
    assert rules["logi-010"]["category"].startswith("Log injection")


def test_unknown_sql_variant_is_trapped_learned_then_denied():
    unknown = httpx.get(f"{GATEWAY}/api/transactions/search", params={"q": 'zz"  ORDER BY 3'})
    assert unknown.headers["X-Verdict"] == "DIVERT"  # not in any DENY rule: sandbox + honeypot study it
    end = time.time() + 15
    learned = []
    while time.time() < end and not learned:
        learned = [r for r in httpx.get(f"{ANALYST}/api/rules").json() if r["source"] == "learned"]
        time.sleep(0.3)
    assert learned, "analyst did not learn a rule for the unknown variant"
    variant = httpx.get(f"{GATEWAY}/api/transactions/search", params={"q": 'yy"  order by 9'})
    assert variant.status_code == 403 and variant.json()["rule_id"] == learned[0]["id"]
    assert variant.json()["owasp"] == "A05"
