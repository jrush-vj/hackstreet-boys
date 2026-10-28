"""G2 (docs/05-phases-and-gates.md): a DIVERT produces gateway + honeypot + sandbox events with the
same correlation_id; A01, A02 and A07 DENY; the dashboard gets live updates over /ws/live.
Needs Abhinav's P2 (rate/path rules, anomaly, DIVERT routing, sandbox) and Akchhat's P2 honeypot.
Run against `docker compose up` in dev: pytest tests/e2e -q"""

import asyncio
import json
import subprocess
import time

import httpx
import pytest
import websockets

from test_g1 import ANALYST, corpus, send


@pytest.fixture(autouse=True)
def reset_rate_counters():
    # rate rules count per IP/account in Redis; earlier runs must not trip this one
    subprocess.run(["docker", "compose", "exec", "-T", "redis", "sh", "-c",
                    "redis-cli --scan --pattern 'rate:*' | xargs -r redis-cli del"],
                   capture_output=True, check=True)


def events_for(rid: str) -> list[dict]:
    events = httpx.get(f"{ANALYST}/api/events", params={"limit": 500}).json()
    return [e for e in events if e["correlation_id"] == rid]


def test_divert_reaches_honeypot_and_sandbox():
    items = [c for c in corpus() if c["expected_verdict"] == "DIVERT"]
    assert items, "corpus has no DIVERT items yet (Abhinav, P2)"
    r = send(items[0])
    assert r.headers["X-Verdict"] == "DIVERT", items[0]["id"]
    rid = r.headers["X-Request-Id"]
    end = time.time() + 8  # sandbox replay is fire-and-forget
    sources = set()
    while time.time() < end and sources != {"gateway", "honeypot", "sandbox"}:
        sources = {e["source"] for e in events_for(rid)}
        time.sleep(0.3)
    assert sources == {"gateway", "honeypot", "sandbox"}, f"{items[0]['id']}: only {sources}"
    sandbox = next(e for e in events_for(rid) if e["source"] == "sandbox")
    assert {"status", "error", "latency_ms", "stack_trace_leaked"} <= set(sandbox["details"])


@pytest.mark.parametrize("owasp", ["A01", "A02", "A07"])
def test_access_config_and_login_rules(owasp):
    # sent in file order, so a burst (A07) can be SAFE first and DENY once over the limit
    items = [c for c in corpus() if c["owasp"] == owasp]
    assert any(c["expected_verdict"] == "DENY" for c in items), f"no {owasp} DENY items yet (Abhinav, P2)"
    for item in items:
        r = send(item)
        assert r.headers["X-Verdict"] == item["expected_verdict"], item["id"]
        if r.status_code == 403:
            assert r.json()["owasp"] == owasp, item["id"]


def test_dashboard_live_feed_over_websocket():
    async def go():
        async with websockets.connect("ws://localhost:3000/ws/live") as ws:  # through nginx
            first = json.loads(await asyncio.wait_for(ws.recv(), 5))
            assert first["type"] == "stats"
            rid = send({"method": "GET", "path": "/api/accounts/1", "query": "", "headers": {},
                        "body": None}).headers["X-Request-Id"]
            while True:
                msg = json.loads(await asyncio.wait_for(ws.recv(), 5))
                if msg["type"] == "event" and msg["data"]["correlation_id"] == rid:
                    return

    asyncio.run(go())
