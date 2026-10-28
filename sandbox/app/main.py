import base64
import binascii
import hashlib
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis_asyncio
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from shared import events
from shared.config import settings
from shared.schemas import Event, RequestInfo

logger = logging.getLogger(__name__)
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    method: str
    path: str = Field(pattern=r"^/")
    query: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body_b64: str = ""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    redis = redis_asyncio.from_url(settings.redis_url, decode_responses=True)
    await redis.ping()
    app.state.redis = redis
    app.state.http = httpx.AsyncClient(timeout=10.0)
    try:
        yield
    finally:
        await app.state.http.aclose()
        await redis.aclose()


app = FastAPI(title="sandbox", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/replay", status_code=202)
async def replay(payload: ReplayRequest, request: Request):
    try:
        body = base64.b64decode(payload.body_b64, validate=True)
    except binascii.Error as exc:
        raise HTTPException(status_code=422, detail="body_b64 must be valid base64") from exc

    headers = {
        name: value
        for name, value in payload.headers.items()
        if name.lower() not in HOP_BY_HOP_HEADERS
        and name.lower() not in {"host", "content-length", "x-verdict"}
    }
    query = f"?{payload.query}" if payload.query else ""
    target = f"{settings.bank_sandbox_url.rstrip('/')}{payload.path}{query}"
    started = time.perf_counter()
    status = 0
    error = None
    try:
        response = await request.app.state.http.request(
            payload.method,
            target,
            headers=headers,
            content=body,
        )
        status = response.status_code
    except httpx.RequestError as exc:
        error = str(exc)
        logger.warning(
            json.dumps(
                {
                    "event": "bank_sandbox_replay_error",
                    "correlation_id": payload.correlation_id,
                    "error": error,
                }
            )
        )
    latency_ms = round((time.perf_counter() - started) * 1000)
    body_text = body.decode("utf-8", errors="replace")
    await events.emit(
        request.app.state.redis,
        Event(
            source="sandbox",
            correlation_id=payload.correlation_id,
            request=RequestInfo(
                method=payload.method,
                path=payload.path,
                query=payload.query,
                ip="sandbox",
                user_agent=payload.headers.get("user-agent", ""),
                body_excerpt=body_text[:500],
                body_sha256=hashlib.sha256(body).hexdigest(),
            ),
            details={
                "status": status,
                "error": error,
                "latency_ms": latency_ms,
                "stack_trace_leaked": False,
            },
        ),
    )
    return {"accepted": True, "correlation_id": payload.correlation_id}
