"""Runs inside the compose network against the live analyst, Redis and Postgres:
    docker compose run --rm analyst pytest -q
Every test cleans up the rows and keys it creates."""

import asyncio
import time
import uuid

import asyncpg
import httpx
import redis.asyncio as aioredis

from app import store
from shared.config import settings
from shared.events import STREAM, emit
from shared.schemas import Event, RequestInfo

API = settings.analyst_url


def _event(**kw) -> Event:
    return Event(source="gateway", correlation_id=f"test-{uuid.uuid4().hex[:8]}",
                 request=RequestInfo(method="GET", path="/test", ip="10.0.0.1"), **kw)


async def _wait_for_event(c: httpx.AsyncClient, ev_id, timeout=5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        feed = (await c.get(f"{API}/api/events", params={"limit": 1000})).json()
        if str(ev_id) in {e["id"] for e in feed}:
            return True
        await asyncio.sleep(0.2)
    return False


async def _conns():
    return (await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2),
            aioredis.from_url(settings.redis_url, decode_responses=True))


def test_event_is_persisted_and_counted():
    ev = _event(verdict="DENY", owasp="A05", rule_id="test-none")

    async def go():
        pool, r = await _conns()
        async with httpx.AsyncClient() as c:
            try:
                before = (await c.get(f"{API}/api/stats")).json()
                await emit(r, ev)
                assert await _wait_for_event(c, ev.id)
                after = (await c.get(f"{API}/api/stats")).json()
                assert after["totals"]["DENY"] == before["totals"]["DENY"] + 1
                assert after["owasp"]["A05"]["DENY"] == before["owasp"]["A05"]["DENY"] + 1
            finally:
                await _cleanup_events(pool, r, [ev.id])

    asyncio.run(go())


def test_bad_message_does_not_block_the_stream():
    ev = _event(verdict="SAFE")

    async def go():
        pool, r = await _conns()
        async with httpx.AsyncClient() as c:
            try:
                await r.xadd(STREAM, {"data": "not json"})
                await emit(r, ev)
                assert await _wait_for_event(c, ev.id)
            finally:
                await _cleanup_events(pool, r, [ev.id])

    asyncio.run(go())


def test_pack_load_and_toggle(tmp_path):
    rid = f"test-{uuid.uuid4().hex[:8]}"
    (tmp_path / "t.yaml").write_text(
        f"- id: {rid}\n  owasp: A05\n  match_type: regex\n  target: query\n"
        f"  pattern: \"(?i)union.+select\"\n  action: DENY\n  description: test rule\n"
    )

    async def go():
        pool, r = await _conns()
        sub = r.pubsub()
        await sub.subscribe(store.RULES_CHANNEL)
        await sub.get_message(timeout=1)  # subscribe ack
        try:
            assert await store.load_packs(pool, r, tmp_path) == 1
            assert await r.hexists(store.RULES_HASH, rid)
            assert (await sub.get_message(timeout=2))["data"] == "*"

            rules = httpx.get(f"{API}/api/rules").json()
            assert any(x["id"] == rid and x["source"] == "pack" for x in rules)

            resp = httpx.patch(f"{API}/api/rules/{rid}", json={"enabled": False})
            assert resp.status_code == 200 and resp.json()["enabled"] is False
            assert not await r.hexists(store.RULES_HASH, rid)
            assert (await sub.get_message(timeout=2))["data"] == rid

            # a restart (pack reload) must keep the runtime toggle
            await store.load_packs(pool, r, tmp_path)
            assert not await r.hexists(store.RULES_HASH, rid)
        finally:
            await pool.execute("DELETE FROM rules WHERE id = $1", rid)
            await r.hdel(store.RULES_HASH, rid)
            await sub.aclose()
            await r.aclose()
            await pool.close()

    asyncio.run(go())


def test_patch_unknown_rule_is_404():
    assert httpx.patch(f"{API}/api/rules/nope-000", json={"enabled": False}).status_code == 404


async def _cleanup_events(pool, r, ids):
    await pool.execute("DELETE FROM events WHERE id = ANY($1::uuid[])", ids)
    await r.aclose()
    await pool.close()
