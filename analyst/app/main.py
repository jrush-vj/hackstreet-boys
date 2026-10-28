"""P0 stub: every contract endpoint from docs/04-system-design.md section 8 (analyst)
returns fixed JSON. Real stream consumer, Postgres and LLM loop come in P1-P3."""

import asyncio
import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from shared.config import settings  # noqa: F401  proves shared/ is wired in
from shared.owasp import OWASP_2025
from shared.schemas import Event, Rule

app = FastAPI(title="analyst")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(event: Event):
    return {"rule": None, "reason": "stub"}


@app.get("/api/events", response_model=list[Event])
def events(since: str | None = None, limit: int = 100):
    return []


@app.get("/api/rules", response_model=list[Rule])
def rules():
    return []


@app.patch("/api/rules/{rule_id}")
def patch_rule(rule_id: str, body: dict):
    return {"id": rule_id, "enabled": bool(body.get("enabled", True))}


@app.get("/api/stats")
def stats():
    return {
        "totals": {"SAFE": 0, "DIVERT": 0, "DENY": 0},
        "owasp": {k: {"DIVERT": 0, "DENY": 0} for k in OWASP_2025},
        "learned_rules": 0,
    }


@app.get("/api/timers")
def timers():
    return []


@app.post("/api/scenario/run")
def scenario_run(body: dict):
    return {"run_id": f"stub-{uuid.uuid4().hex[:8]}"}


@app.websocket("/ws/live")
async def live(ws: WebSocket):
    await ws.accept()
    try:
        await ws.send_json({"type": "stats", "data": stats()})
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        pass
