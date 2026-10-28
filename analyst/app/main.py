"""Analyst: consumes `events`, persists to Postgres, owns the rules, serves the dashboard API.
Contracts: docs/04-system-design.md sections 6, 8 (analyst), 9, 11.
P3: every gateway DIVERT goes through the learning loop (app/learner.py); /analyze and /api/timers are real.
/api/scenario/run is still a stub (P4)."""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from shared.config import settings
from shared.owasp import OWASP_2025
from shared.schemas import Event, Rule

from app import consumer, learner, store
from app.hp import HpHub, _llm_cfg, router as hp_router
from app.live import Hub

PACKS_DIR = Path("/app/packs")  # gateway/rules/packs, mounted read-only by compose


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=5)
    app.state.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    await store.migrate(app.state.pool)
    await store.load_packs(app.state.pool, app.state.redis, PACKS_DIR)
    app.state.hub = hub = Hub()
    app.state.hp_hub = hp_hub = HpHub(app.state.redis)
    app.state.packs_dir = PACKS_DIR
    app.state.learn_lock = asyncio.Lock()
    app.state.llm_status = {"state": "idle", "last_latency_ms": None, "last_error": None}
    app.state.llm_cfg = _llm_cfg
    learning: set[asyncio.Task] = set()

    async def on_event(ev):
        await hub.on_event(ev)
        await hp_hub.on_event(ev)
        if ev.source == "gateway" and ev.verdict == "DIVERT":  # possible zero-day: learn from it
            t = asyncio.create_task(learn_safely(app, ev))
            learning.add(t)
            t.add_done_callback(learning.discard)

    tasks = [
        asyncio.create_task(consumer.run(app.state.pool, app.state.redis, on_event=on_event)),
        asyncio.create_task(hub.stats_loop(lambda: store.stats(app.state.pool, OWASP_2025))),
    ]
    store.log("analyst started", llm_mode=settings.llm_mode)
    yield
    for t in tasks:
        t.cancel()
    await app.state.redis.aclose()
    await app.state.pool.close()


app = FastAPI(title="analyst", lifespan=lifespan)
app.include_router(hp_router)  # honeypot console API: /api/hp/*, /ws/hp


@app.get("/health")
def health():
    return {"status": "ok"}


async def learn_safely(app: FastAPI, ev: Event, from_stream: bool = True):
    try:
        return await learner.learn(app.state, ev, from_stream)
    except Exception as e:  # a failed analysis must never stop the consumer
        store.log("learning failed", correlation_id=ev.correlation_id, error=repr(e))
        return None, f"error: {e!r}"


@app.post("/analyze")
async def analyze(event: Event, request: Request):
    rule, reason = await learn_safely(request.app, event, from_stream=False)
    return {"rule": rule.model_dump(mode="json") if rule else None, "reason": reason}


@app.get("/api/events", response_model=list[Event])
async def events(request: Request, since: datetime | None = None,
                 limit: int = Query(100, ge=1, le=1000)):
    return await store.list_events(request.app.state.pool, since, limit)


@app.get("/api/rules", response_model=list[Rule])
async def rules(request: Request):
    return await store.list_rules(request.app.state.pool)


class RulePatch(BaseModel):
    enabled: bool


@app.patch("/api/rules/{rule_id}", response_model=Rule)
async def patch_rule(rule_id: str, body: RulePatch, request: Request):
    rule = await store.set_enabled(request.app.state.pool, rule_id, body.enabled)
    if rule is None:
        raise HTTPException(404, f"no rule {rule_id}")
    await store.publish_rule(request.app.state.redis, rule)
    await request.app.state.hub.on_rule(rule)
    return rule


@app.get("/api/stats")
async def stats(request: Request):
    return await store.stats(request.app.state.pool, OWASP_2025)


@app.get("/api/timers")
async def timers(request: Request):
    """Per learned rule: pattern first seen → rule created → first DENY by that rule (seconds)."""
    rows = await request.app.state.pool.fetch("""
        SELECT m.rule_id, m.owasp, m.first_seen, r.created_at AS rule_created,
               (SELECT min(e.ts) FROM events e WHERE e.source = 'gateway' AND e.verdict = 'DENY'
                AND e.rule_id = m.rule_id) AS first_blocked
        FROM learned_meta m JOIN rules r ON r.id = m.rule_id ORDER BY m.first_seen DESC""")
    return [{"rule_id": r["rule_id"], "owasp": r["owasp"], "first_seen": r["first_seen"],
             "rule_created": r["rule_created"], "first_blocked": r["first_blocked"],
             "seconds": round((r["first_blocked"] - r["first_seen"]).total_seconds(), 1)}
            for r in rows if r["first_blocked"]]


@app.post("/api/scenario/run")
def scenario_run(body: dict):
    return {"run_id": f"stub-{uuid.uuid4().hex[:8]}"}


@app.websocket("/ws/live")
async def live(ws: WebSocket):
    await ws.accept()
    hub = ws.app.state.hub
    try:
        await ws.send_json({"type": "stats", "data": await store.stats(ws.app.state.pool, OWASP_2025)})
        hub.clients.add(ws)
        while True:
            await ws.receive_text()  # clients don't send; this just notices the disconnect
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)
