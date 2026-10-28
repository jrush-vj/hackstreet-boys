"""Honeypot console (sentinel-trap replica at /honeypot/) end to end, through the dashboard's nginx:
a DIVERT becomes a trapped session, a reused canary key bans the IP, reset clears it, /ws/hp is live."""

import asyncio
import json
import time

import httpx
import websockets

from test_g1 import corpus, send

UI = "http://localhost:3000"
ADMIN = {"X-Admin-Token": "dev-admin-token"}
CANARY = "vb_live_CANARY_0123456789ab"


def reset():
    assert httpx.post(f"{UI}/api/hp/reset", headers=ADMIN).status_code == 200


def test_console_page_is_served():
    page = httpx.get(f"{UI}/honeypot/")
    assert page.status_code == 200 and "Honeypot" in page.text and "/honeypot/app.js" in page.text
    assert httpx.get(f"{UI}/honeypot/app.js").status_code == 200
    assert httpx.get(f"{UI}/honeypot/fonts/ibm-plex-sans-latin-400-normal.woff2").status_code == 200


def test_divert_shows_up_as_trapped_session():
    item = next(c for c in corpus() if c["expected_verdict"] == "DIVERT")
    rid = send(item).headers["X-Request-Id"]
    end = time.time() + 8
    while time.time() < end:
        sessions = httpx.get(f"{UI}/api/hp/sessions").json()
        if sessions and sessions[0]["actions"] >= 1:
            break
        time.sleep(0.3)
    s = sessions[0]
    assert s["status"] == "trapped" and s["actions"] >= 1
    assert any(t["action"] == "routed_to_honeypot" for t in s["timeline"])
    events = httpx.get(f"{UI}/api/hp/events", params={"limit": 50}).json()
    assert {"routed_to_honeypot", "honeypot_interaction"} <= {e["action"] for e in events}
    stats = httpx.get(f"{UI}/api/hp/stats").json()
    assert stats["attackers_trapped"] >= 1 and stats["by_action"]["routed_to_honeypot"] >= 1
    assert rid


def test_canary_reuse_shows_a_temporary_ban_only():
    caught = send({"method": "GET", "path": "/api/accounts/1", "query": "",
                   "headers": {"authorization": f"Bearer {CANARY}"}, "body": None})
    assert caught.status_code == 403 and caught.json()["rule_id"] == "canary-001"
    end = time.time() + 5
    while time.time() < end and not httpx.get(f"{UI}/api/hp/bans").json():
        time.sleep(0.2)
    bans = httpx.get(f"{UI}/api/hp/bans").json()
    assert bans and "canary" in bans[0]["reason"] and "display only" in bans[0]["reason"]
    # display-only: the same client keeps being judged per request, nobody is locked out
    after = send({"method": "GET", "path": "/api/accounts/1", "query": "", "headers": {}, "body": None})
    assert after.status_code == 200 and after.headers["X-Verdict"] == "SAFE"
    assert httpx.post(f"{UI}/api/hp/reset").status_code == 401  # write actions need the admin token
    reset()
    assert httpx.get(f"{UI}/api/hp/bans").json() == []


def test_live_console_feed():
    async def go():
        async with websockets.connect("ws://localhost:3000/ws/hp") as ws:
            send({"method": "GET", "path": "/api/accounts/2", "query": "", "headers": {}, "body": None})
            while True:
                msg = json.loads(await asyncio.wait_for(ws.recv(), 5))
                if msg["type"] == "event" and msg["event"]["action"] == "request":
                    return msg["event"]

    ev = asyncio.run(go())
    assert ev["payload"].startswith("/api/accounts/2")
