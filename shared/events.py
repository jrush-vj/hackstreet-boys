from shared.schemas import Event

STREAM = "events"


async def emit(redis, event: Event) -> None:
    """XADD events * data <json>. `redis` is a redis.asyncio.Redis client."""
    await redis.xadd(STREAM, {"data": event.model_dump_json()})
