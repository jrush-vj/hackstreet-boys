"""Consumer group on the Redis stream `events`: every event is persisted to Postgres."""

import asyncio
import socket

import asyncpg
from pydantic import ValidationError
from redis.exceptions import ResponseError

from shared.events import STREAM
from shared.schemas import Event

from app import store

GROUP = "analyst"


async def ensure_group(redis) -> None:
    try:
        # id "0": a fresh group also picks up events emitted before the analyst first started
        await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


async def handle(pool, redis, msg_id: str, fields: dict) -> Event | None:
    try:
        ev = Event.model_validate_json(fields["data"])
    except (KeyError, ValidationError) as e:
        # a bad message must not block the stream: log it and ack it
        store.log("bad event dropped", stream_id=msg_id, error=str(e)[:300])
        ev = None
    else:
        try:
            await store.save_event(pool, ev)
        except asyncpg.DataError as e:
            # a message Postgres can never store (e.g. a NUL in a body): drop it, or it blocks the whole stream
            store.log("event dropped", stream_id=msg_id, error=str(e)[:200])
    await redis.xack(STREAM, GROUP, msg_id)
    return ev


async def run(pool, redis, on_event=None) -> None:
    """Forever: first drain our own pending (unacked) messages, then read new ones."""
    await ensure_group(redis)
    consumer = socket.gethostname()
    start = "0"
    while True:
        try:
            resp = await redis.xreadgroup(GROUP, consumer, {STREAM: start}, count=100, block=1000)
            msgs = resp[0][1] if resp else []
            if start == "0" and not msgs:
                start = ">"
                continue
            for msg_id, fields in msgs:
                ev = await handle(pool, redis, msg_id, fields)
                if ev and on_event:
                    await on_event(ev)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # keep consuming if Postgres/Redis blips
            store.log("consumer error", error=repr(e))
            await asyncio.sleep(1)
