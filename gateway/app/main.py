import asyncio
import hashlib
import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis_asyncio
from redis.asyncio import Redis
from redis.asyncio.client import PubSub
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from shared import events
from shared.config import settings
from shared.schemas import Event, RequestInfo

from .engine import RequestContext, RuleEngine, load_active_rules

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
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


async def reload_active_rules(redis: Redis, engine: RuleEngine) -> None:
    engine.replace_rules(await load_active_rules(redis))


async def listen_for_rule_updates(
    redis: Redis, pubsub: PubSub, engine: RuleEngine
) -> None:
    await pubsub.subscribe("rules:updated")
    async for message in pubsub.listen():
        if message.get("type") == "message":
            await reload_active_rules(redis, engine)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    redis = redis_asyncio.from_url(settings.redis_url, decode_responses=True)
    await redis.ping()
    engine = RuleEngine()
    await reload_active_rules(redis, engine)
    pubsub = redis.pubsub()
    app.state.redis = redis
    app.state.engine = engine
    app.state.http = httpx.AsyncClient(timeout=30.0)
    app.state.pubsub = pubsub
    app.state.rule_listener = asyncio.create_task(
        listen_for_rule_updates(redis, pubsub, engine)
    )
    try:
        yield
    finally:
        app.state.rule_listener.cancel()
        try:
            await app.state.rule_listener
        except asyncio.CancelledError:
            pass
        await pubsub.aclose()
        await app.state.http.aclose()
        await redis.aclose()


app = FastAPI(title="gateway", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.api_route("/", methods=PROXY_METHODS)
@app.api_route("/{path:path}", methods=PROXY_METHODS)
async def proxy(request: Request, path: str = ""):
    request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    body = await request.body()
    body_text = body.decode("utf-8", errors="replace")
    client = request.client
    ip = client.host if client else "unknown"
    context = RequestContext(
        path=request.url.path,
        query=request.url.query,
        headers=dict(request.headers),
        body=body_text,
    )
    rule = request.app.state.engine.evaluate(context)
    verdict = rule.action if rule else "SAFE"
    matched_owasp = rule.owasp if rule else None
    matched_rule_id = rule.id if rule else None
    scenario_step = request.headers.get("X-Scenario-Step")

    if verdict == "DENY":
        response = JSONResponse(
            {
                "verdict": "DENY",
                "rule_id": matched_rule_id,
                "owasp": matched_owasp,
                "request_id": request_id,
            },
            status_code=403,
        )
    else:
        request_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
            and key.lower() not in {"host", "content-length", "x-verdict"}
        }
        request_headers["X-Request-Id"] = request_id
        query = f"?{request.url.query}" if request.url.query else ""
        bank_url = f"{settings.bank_url.rstrip('/')}{request.url.path}{query}"
        try:
            upstream = await request.app.state.http.request(
                request.method,
                bank_url,
                headers=request_headers,
                content=body,
            )
            response_headers = {
                key: value
                for key, value in upstream.headers.items()
                if key.lower() not in HOP_BY_HOP_HEADERS
                and key.lower()
                not in {"content-length", "content-encoding", "date", "server"}
            }
            response = Response(
                content=upstream.content,
                status_code=upstream.status_code,
                headers=response_headers,
            )
        except httpx.RequestError as exc:
            logger.warning(
                json.dumps(
                    {
                        "event": "bank_upstream_error",
                        "request_id": request_id,
                        "error": str(exc),
                    }
                )
            )
            response = JSONResponse(
                {"detail": "Bank upstream unavailable", "request_id": request_id},
                status_code=502,
            )

    event = Event(
        source="gateway",
        correlation_id=request_id,
        verdict=verdict,
        owasp=matched_owasp,
        rule_id=matched_rule_id,
        request=RequestInfo(
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            ip=ip,
            user_agent=request.headers.get("user-agent", ""),
            body_excerpt=body_text[:500],
            body_sha256=hashlib.sha256(body).hexdigest(),
        ),
        scenario_step=scenario_step,
    )
    await events.emit(request.app.state.redis, event)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Verdict"] = verdict
    return response
