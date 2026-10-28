import base64
import binascii
import hashlib
import json
import logging
import os
import re
import resource
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis_asyncio
from fastapi import FastAPI, HTTPException, Request, Response
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
PYTHON_TRACEBACK_HEADER = re.compile(r"(?m)^Traceback \(most recent call last\):\s*$")
PYTHON_TRACEBACK_FRAME = re.compile(r'(?m)^\s+File "[^"]+", line \d+')


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


def looks_like_python_traceback(status_code: int, body: str) -> bool:
    return (
        status_code == 500
        and PYTHON_TRACEBACK_HEADER.search(body) is not None
        and PYTHON_TRACEBACK_FRAME.search(body) is not None
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/replay", status_code=202)
async def replay(payload: ReplayRequest, request: Request):
    try:
        body = base64.b64decode(payload.body_b64, validate=True)
    except binascii.Error as exc:
        raise HTTPException(
            status_code=422, detail="body_b64 must be valid base64"
        ) from exc

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
    stack_trace_leaked = False
    try:
        response = await request.app.state.http.request(
            payload.method,
            target,
            headers=headers,
            content=body,
        )
        status = response.status_code
        stack_trace_leaked = looks_like_python_traceback(
            status,
            response.text[:8192],
        )
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
                "stack_trace_leaked": stack_trace_leaked,
            },
        ),
    )
    return {"accepted": True, "correlation_id": payload.correlation_id}


# ---------------------------------------------------------------- /scan: static upload scanning

MAX_UPLOAD = 5 * 1024 * 1024
SCAN_TIMEOUT_S = 10


def _scan_limits() -> None:
    """Runs in the child just before the scanner starts: no disk writes, bounded memory, CPU and fds."""
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (SCAN_TIMEOUT_S, SCAN_TIMEOUT_S))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def run_scanner(data: bytes) -> dict:
    """Scan in an isolated child. Any failure is reported as scan_error, and the gateway then diverts (fails closed)."""
    try:
        out = subprocess.run(
            [sys.executable, "-m", "app.scanner"], input=data, capture_output=True,
            timeout=SCAN_TIMEOUT_S, preexec_fn=_scan_limits,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        if out.returncode != 0:
            raise RuntimeError(out.stderr[-300:].decode("utf-8", "replace"))
        return json.loads(out.stdout)
    except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError) as exc:
        logger.warning(json.dumps({"event": "scan_error", "error": str(exc)[:200]}))
        return {"verdict": "DIVERT", "rule_id": "scan-error", "score": 1.0,
                "components": {"scan_error": 1.0}, "findings": ["scanner failed: the file was not analysed"],
                "entries": 0, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


@app.post("/scan")
async def scan(request: Request) -> Response:
    data = await request.body()
    if len(data) > MAX_UPLOAD:
        return Response(status_code=413, content=json.dumps({"detail": "upload too large"}), media_type="application/json")
    result = run_scanner(data)
    return Response(content=json.dumps(result), media_type="application/json")
