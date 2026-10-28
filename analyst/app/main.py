"""Analyst: consumes `events`, persists to Postgres, owns the rules, serves the dashboard API.
Contracts: docs/04-system-design.md sections 6, 8 (analyst), 9, 11.
P1/P2: events, stats, rules and /ws/live are real. /analyze, timers and scenario are still stubs."""

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

from app import consumer, store
from app.live import Hub

PACKS_DIR = Path("/app/packs")  # gateway/rules/packs, mounted read-only by compose


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=5)
    app.state.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    await store.migrate(app.state.pool)
    await store.load_packs(app.state.pool, app.state.redis, PACKS_DIR)
    app.state.hub = hub = Hub()
    tasks = [
        asyncio.create_task(consumer.run(app.state.pool, app.state.redis, on_event=hub.on_event)),
        asyncio.create_task(hub.stats_loop(lambda: store.stats(app.state.pool, OWASP_2025))),
    ]
    store.log("analyst started", llm_mode=settings.llm_mode)
    yield
    for t in tasks:
        t.cancel()
    await app.state.redis.aclose()
    await app.state.pool.close()


app = FastAPI(title="analyst", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(event: Event):
    return {"rule": None, "reason": "stub"}


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
def timers():
    return []


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
