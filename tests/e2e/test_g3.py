"""G3 (docs/05-phases-and-gates.md): the zero-day moment. An unseen A06 pattern is DIVERTed, a rule is
learned and shown, the next similar request is DENYed, and the timer has the seconds. Also the offline
(canned) path, /analyze, and the sandbox spotting a leaked stack trace (A10).
Runs in mock mode; Jerush runs it by hand in kaggle/local modes. Run against the dev stack: pytest tests/e2e -q"""

import time

import httpx

from test_g1 import ANALYST, GATEWAY, corpus, send

ADMIN = {"X-Admin-Token": "dev-admin-token"}


def learned_rule(owasp: str, timeout: float = 15) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        rules = [r for r in httpx.get(f"{ANALYST}/api/rules").json() if r["source"] == "learned" and r["owasp"] == owasp]
        if rules:
            return rules[0]
        time.sleep(0.3)
    raise AssertionError(f"no {owasp} rule learned within {timeout}s")


def warm_up_safe_traffic():
    for item in [c for c in corpus() if c["label"] == "benign"][:10]:
        send(item)


def test_zero_day_moment():
    warm_up_safe_traffic()
    probe = next(c for c in corpus() if c["id"] == "c-0053")
    first = send(probe)
    assert first.headers["X-Verdict"] == "DIVERT"  # first sight: unknown, studied in the honeypot

    rule = learned_rule("A06")
    assert rule["id"].startswith("L-") and rule["action"] == "DENY" and rule["enabled"]

    variant = httpx.post(f"{GATEWAY}/api/transfer",
                         json={"from_account_id": 12, "to_account_id": 40, "amount": 99.0, "note": "&&**!!@@##$$%%^^&&**"})
    assert variant.status_code == 403 and variant.json()["rule_id"] == rule["id"]
    normal = httpx.post(f"{GATEWAY}/api/transfer", json={"from_account_id": 3, "to_account_id": 18, "amount": 1.0})
    assert normal.headers["X-Verdict"] == "SAFE"

    time.sleep(1.5)  # the DENY event reaches the analyst
    timers = httpx.get(f"{ANALYST}/api/timers").json()
    assert timers and timers[0]["rule_id"] == rule["id"] and 0 < timers[0]["seconds"] < 30
    assert httpx.get(f"{ANALYST}/api/stats").json()["owasp"]["A06"]["DIVERT"] >= 1  # anomaly DIVERT got its category
    notes = httpx.get(f"{ANALYST}/api/hp/analyses").json()
    assert notes and notes[0]["rule_id"] == rule["id"] and notes[0]["source"] == "llm"


def test_offline_canned_path_when_ai_is_off():
    httpx.post(f"{ANALYST}/api/hp/llm/config", headers=ADMIN, json={"enabled": False})
    try:
        warm_up_safe_traffic()
        probe = next(c for c in corpus() if c["id"] == "c-0055")  # A10: malformed account id
        assert send(probe).headers["X-Verdict"] == "DIVERT"
        rule = learned_rule("A10")
        again = httpx.get(f"{GATEWAY}/api/accounts/also-not-a-number")
        assert again.status_code == 403 and again.json()["rule_id"] == rule["id"]
        assert httpx.get(f"{ANALYST}/api/hp/analyses").json()[0]["source"] == "offline"
    finally:
        httpx.post(f"{ANALYST}/api/hp/llm/config", headers=ADMIN, json={"enabled": True})


def test_analyze_endpoint_returns_a_rule():
    ev = {"source": "gateway", "correlation_id": "g3-analyze", "verdict": "DIVERT",
          "request": {"method": "POST", "path": "/api/login", "query": "", "ip": "10.9.9.9",
                      "body_excerpt": '{"email": "x@y.test", "credential": "aaa", "override": "bbb"}'}}
    out = httpx.post(f"{ANALYST}/analyze", json=ev, timeout=60).json()
    assert out["rule"] and out["rule"]["owasp"] == "A07" and out["rule"]["source"] == "learned", out["reason"]


def test_sandbox_spots_a_leaked_stack_trace():
    r = httpx.get(f"{GATEWAY}/api/accounts/!!x", params={"unexpected": "<>/\\;:!@#$%^&*()" * 3})
    assert r.headers["X-Verdict"] == "DIVERT", "probe should be anomalous enough to divert"
    rid = r.headers["X-Request-Id"]
    end = time.time() + 8
    while time.time() < end:
        sb = [e for e in httpx.get(f"{ANALYST}/api/events", params={"limit": 200}).json()
              if e["correlation_id"] == rid and e["source"] == "sandbox"]
        if sb:
            break
        time.sleep(0.3)
    assert sb and sb[0]["details"]["status"] == 500 and sb[0]["details"]["stack_trace_leaked"] is True
