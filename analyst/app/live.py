"""WS /ws/live fan-out: {"type": "event"|"rule"|"stats", "data": {...}} (design doc section 8)."""

import asyncio

from fastapi import WebSocket

from shared.schemas import Event, Rule

SEND_TIMEOUT_S = 1.0
STATS_EVERY_S = 1.0


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.stats_dirty = False

    async def broadcast(self, type_: str, data: dict) -> None:
        # shortcut: sends to each client in turn (a slow one delays the rest by up to 1 s); use per-client queues if the audience grows
        for ws in list(self.clients):
            try:
                await asyncio.wait_for(ws.send_json({"type": type_, "data": data}), SEND_TIMEOUT_S)
            except Exception:
                self.clients.discard(ws)

    async def on_event(self, ev: Event) -> None:
        self.stats_dirty = True
        if self.clients:
            await self.broadcast("event", ev.model_dump(mode="json"))

    async def on_rule(self, rule: Rule) -> None:
        self.stats_dirty = True  # learned_rules count may change
        if self.clients:
            await self.broadcast("rule", rule.model_dump(mode="json"))

    async def stats_loop(self, get_stats) -> None:
        """Stats at most once a second, so a burst of 100 events costs one query, not 100."""
        while True:
            await asyncio.sleep(STATS_EVERY_S)
            if self.stats_dirty and self.clients:
                self.stats_dirty = False
                try:
                    await self.broadcast("stats", await get_stats())
                except Exception:  # Postgres blip: try again next tick
                    self.stats_dirty = True
