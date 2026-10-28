import asyncio
import base64
import hashlib
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from redis.asyncio import Redis
from redis.asyncio.client import PubSub

from shared import events
from shared.config import settings
from shared.schemas import Event, RequestInfo

from .anomaly import score_request
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
BANS_KEY = "bans:ip"  # banned client IPs (canary reuse, or banned from the honeypot console)
BANS_INFO_KEY = "bans:info"  # ip -> {"reason", "ts"}
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
SESSION_OWNER_TTL_SECONDS = 3600


async def reload_active_rules(redis: Redis, engine: RuleEngine) -> None:
    engine.replace_rules(await load_active_rules(redis))


async def listen_for_rule_updates(
    redis: Redis, pubsub: PubSub, engine: RuleEngine
) -> None:
    await pubsub.subscribe("rules:updated")
    async for message in pubsub.listen():
        if message.get("type") == "message":
            await reload_active_rules(redis, engine)


def response_headers(upstream: httpx.Response) -> dict[str, str]:
    return {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
        and key.lower() not in {"content-length", "content-encoding", "date", "server"}
    }


def proxy_url(base: str, request: Request) -> str:
    query = f"?{request.url.query}" if request.url.query else ""
    return f"{base.rstrip('/')}{request.url.path}{query}"


def bearer_token(headers: dict[str, str]) -> str | None:
    authorization = headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


async def remember_login_owner(
    redis: Redis, request: Request, response: httpx.Response
) -> None:
    if request.url.path != "/api/login" or not 200 <= response.status_code < 300:
        return
    try:
        payload = response.json()
        token = payload["token"]
        owner_id = payload["customer"]["id"]
        if not isinstance(token, str) or not token or not isinstance(owner_id, int):
            raise TypeError("invalid token or customer id")
    except (ValueError, KeyError, TypeError):
        logger.warning(
            json.dumps(
                {
                    "event": "login_response_missing_session_identity",
                    "request_id": request.headers.get("X-Request-Id"),
                }
            )
        )
        return
    token_key = hashlib.sha256(token.encode()).hexdigest()
    await redis.set(
        f"session-owner:{token_key}",
        str(owner_id),
        ex=SESSION_OWNER_TTL_SECONDS,
    )


async def session_owner(redis: Redis, headers: dict[str, str]) -> str | None:
    token = bearer_token(headers)
    if token is None:
        return None
    token_key = hashlib.sha256(token.encode()).hexdigest()
    return await redis.get(f"session-owner:{token_key}")


async def replay_in_sandbox(
    app: FastAPI,
    request: Request,
    body: bytes,
    request_id: str,
) -> None:
    replay_payload = {
        "correlation_id": request_id,
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query,
        "headers": dict(request.headers),
        "body_b64": base64.b64encode(body).decode("ascii"),
    }
    try:
        response = await app.state.http.post(
            f"{settings.sandbox_url.rstrip('/')}/replay", json=replay_payload
        )
        if response.status_code != 202:
            logger.warning(
                json.dumps(
                    {
                        "event": "sandbox_replay_rejected",
                        "request_id": request_id,
                        "status": response.status_code,
                    }
                )
            )
    except httpx.RequestError as exc:
        logger.warning(
            json.dumps(
                {
                    "event": "sandbox_replay_error",
                    "request_id": request_id,
                    "error": str(exc),
                }
            )
        )


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
    app.state.background_tasks = set()
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
        for task in app.state.background_tasks:
            task.cancel()
        if app.state.background_tasks:
            await asyncio.gather(*app.state.background_tasks, return_exceptions=True)
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
        ip=ip,
    )
    redis = request.app.state.redis
    banned = await redis.sismember(BANS_KEY, ip)
    rule = None if banned else await request.app.state.engine.evaluate(context, redis)
    if rule is not None and rule.id.startswith("canary-"):
        # a planted honeypot key came back: whoever sent it is an attacker, ban the IP for good
        await redis.sadd(BANS_KEY, ip)
        await redis.hset(BANS_INFO_KEY, ip, json.dumps({"reason": f"reused a canary key ({rule.id})", "ts": time.time()}))
    verdict = "DENY" if banned else (rule.action if rule else "SAFE")
    matched_owasp = rule.owasp if rule else None
    matched_rule_id = "banned" if banned else (rule.id if rule else None)
    scenario_step = request.headers.get("X-Scenario-Step")
    score = 0.0
    score_details = {}
    if rule is None and not banned:
        score, score_details = score_request(context)
        if score >= settings.divert_threshold:
            verdict = "DIVERT"

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
        upstream_base = (
            settings.honeypot_url if verdict == "DIVERT" else settings.bank_url
        )
        upstream_name = "honeypot" if verdict == "DIVERT" else "bank"
        try:
            upstream = await request.app.state.http.request(
                request.method,
                proxy_url(upstream_base, request),
                headers=request_headers,
                content=body,
            )
            if verdict == "SAFE" and request.url.path == "/api/login":
                await remember_login_owner(request.app.state.redis, request, upstream)
            if verdict == "SAFE" and request.url.path.startswith("/api/accounts/"):
                owner_id = await session_owner(
                    request.app.state.redis, dict(request.headers)
                )
                if owner_id is not None and upstream.status_code == 200:
                    try:
                        account_id = upstream.json()["account"]["customer_id"]
                    except (ValueError, KeyError, TypeError):
                        account_id = None
                    if account_id is None:
                        logger.warning(
                            json.dumps(
                                {
                                    "event": "account_response_missing_owner",
                                    "request_id": request_id,
                                }
                            )
                        )
                        response = JSONResponse(
                            {
                                "detail": "Bank account response unavailable",
                                "request_id": request_id,
                            },
                            status_code=502,
                        )
                    elif str(account_id) != owner_id:
                        verdict = "DENY"
                        matched_owasp = "A01"
                        matched_rule_id = "access-account-owner"
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
                        response = Response(
                            content=upstream.content,
                            status_code=upstream.status_code,
                            headers=response_headers(upstream),
                        )
                else:
                    response = Response(
                        content=upstream.content,
                        status_code=upstream.status_code,
                        headers=response_headers(upstream),
                    )
            else:
                response = Response(
                    content=upstream.content,
                    status_code=upstream.status_code,
                    headers=response_headers(upstream),
                )
            if verdict == "DIVERT":
                task = asyncio.create_task(
                    replay_in_sandbox(request.app, request, body, request_id)
                )
                request.app.state.background_tasks.add(task)
                task.add_done_callback(request.app.state.background_tasks.discard)
        except httpx.RequestError as exc:
            logger.warning(
                json.dumps(
                    {
                        "event": f"{upstream_name}_upstream_error",
                        "request_id": request_id,
                        "error": str(exc),
                    }
                )
            )
            response = JSONResponse(
                {
                    "detail": f"{upstream_name.capitalize()} upstream unavailable",
                    "request_id": request_id,
                },
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
        details={"anomaly_components": score_details} if score_details else {},
    )
    await events.emit(request.app.state.redis, event)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Verdict"] = verdict
    return response
