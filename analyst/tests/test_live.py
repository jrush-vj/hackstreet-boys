"""WS /ws/live against the running analyst: docker compose run --rm analyst pytest -q"""

import asyncio
import json
import uuid

import asyncpg
import httpx
import redis.asyncio as aioredis
import websockets

from app import store
from shared.config import settings
from shared.events import emit
from shared.schemas import Event, RequestInfo, Rule

WS = settings.analyst_url.replace("http://", "ws://") + "/ws/live"


async def _next(ws, type_, pred=lambda d: True, timeout=5.0) -> dict:
    """Read messages until one of `type_` matches `pred`."""
    async def loop():
        while True:
            msg = json.loads(await ws.recv())
            if msg["type"] == type_ and pred(msg["data"]):
                return msg["data"]
    return await asyncio.wait_for(loop(), timeout)


def test_live_pushes_stats_events_and_rules():
    async def go():
        pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        rid = f"test-{uuid.uuid4().hex[:8]}"
        ev = Event(source="gateway", correlation_id=f"test-{uuid.uuid4().hex[:8]}", verdict="SAFE",
                   request=RequestInfo(method="GET", path="/live-test", ip="10.0.0.1"))
        try:
            async with websockets.connect(WS) as ws:
                first = json.loads(await asyncio.wait_for(ws.recv(), 5))
                assert first["type"] == "stats" and set(first["data"]["totals"]) == {"SAFE", "DIVERT", "DENY"}

                await emit(r, ev)
                got = await _next(ws, "event", lambda d: d["id"] == str(ev.id))
                assert got["request"]["path"] == "/live-test"
                await _next(ws, "stats")  # throttled stats follow a new event

                await store.upsert_rule(pool, Rule(id=rid, owasp="A05", match_type="regex",
                                                   pattern="abc", action="DENY", source="pack",
                                                   description="live test"))
                async with httpx.AsyncClient() as c:
                    resp = await c.patch(f"{settings.analyst_url}/api/rules/{rid}", json={"enabled": False})
                    assert resp.status_code == 200
                rule = await _next(ws, "rule", lambda d: d["id"] == rid)
                assert rule["enabled"] is False
        finally:
            await pool.execute("DELETE FROM events WHERE id = $1", ev.id)
            await pool.execute("DELETE FROM rules WHERE id = $1", rid)
            await r.hdel(store.RULES_HASH, rid)
            await r.aclose()
            await pool.close()

    asyncio.run(go())
