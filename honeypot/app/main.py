"""VulnBank honeypot (:8002, internal only). Same routes and response shapes as the bank, decoy data.

Ported from sentinel-trap's honeypot: payload-aware decoys with canary keys, decoy endpoints
(robots.txt, .env, internal keys), believable latency, and a per-session fake activity log. Bodies are
parsed leniently so odd input never gets a tell-tale 422. Every request becomes a `source="honeypot"`
event whose details say what was served, so the honeypot console can show real vs decoy data.
"""

import asyncio
import json
import logging
import random
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from honeypot.app import fakes
from shared.config import settings
from shared.events import emit
from shared.schemas import Event, RequestInfo

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("honeypot")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        yield
    finally:
        await app.state.redis.aclose()


app = FastAPI(title="VulnBank Honeypot", lifespan=lifespan, docs_url=None, redoc_url=None)
FAKE_LOG = [
    "2026-10-28T08:59:12Z INFO user=ops action=login",
    "2026-10-28T09:02:47Z INFO user=payments-service action=batch_run status=ok",
]
session_logs: dict[str, list[str]] = {}  # per attacker IP: forged lines only they ever see


def served(request: Request, what: str, kind: str = "", sample: Any = None, category: str = "",
           canary: bool = False) -> None:
    """Record what this request was served; the middleware puts it on the event."""
    request.state.hp = {"served": what, "kind": kind, "sample": sample, "category": category, "canary": canary}


async def body_of(request: Request) -> dict:
    try:
        data = json.loads(await request.body() or b"{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


async def emit_event(request: Request, body: bytes) -> None:
    hp = getattr(request.state, "hp", {"served": "generic decoy 200"})
    event = Event(
        source="honeypot",
        # the gateway forwards its X-Request-Id, which links this event to the DIVERT
        correlation_id=request.headers.get("x-request-id", ""),
        request=RequestInfo(
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            ip=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", ""),
            body_excerpt=body.decode("utf-8", errors="replace")[:500],
        ),
        details={"route": request.url.path, "action": f"{request.method} {request.url.path}", **hp},
    )
    try:
        await emit(request.app.state.redis, event)
    except Exception as error:  # never fail the attacker's response because Redis blipped
        logger.error("honeypot event emission failed: %s", error)


@app.middleware("http")
async def event_middleware(request: Request, call_next):
    if request.url.path == "/health":  # Docker healthchecks every 10 s are not attacker traffic
        return await call_next(request)
    body = await request.body()
    await asyncio.sleep(random.uniform(0.05, 0.30))  # believable latency, like a real DB round trip
    response = await call_next(request)
    await emit_event(request, body)
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/login")
async def login(request: Request) -> dict[str, Any]:
    email = str((await body_of(request)).get("email", "customer"))
    served(request, "decoy login accepted", category="auth")
    return {"ok": True, "token": fakes.canary_token("login"), "customer": {"id": 501, "name": email.split("@")[0].title()}}


@app.api_route("/api/accounts/{account_id}", methods=["GET", "POST"])
def account(account_id: str, request: Request) -> dict[str, Any]:
    acct = int(account_id) if account_id.isdigit() else 501
    served(request, "decoy account")
    return {"account": {"id": acct, "account_number": f"ACCT-{acct + 70000000:08d}", "balance": 5000.0,
                        "customer_id": 501, "customer_name": "Demo Customer"}}


@app.post("/api/transfer")
async def transfer(request: Request) -> dict[str, Any]:
    amount = (await body_of(request)).get("amount", 0)
    served(request, "decoy transfer: reported as success, nothing moved", category="transfer")
    return {"ok": True, "amount": amount}


@app.get("/api/transactions/search")
def search_transactions(request: Request, q: str = "") -> dict[str, Any]:
    rows, what, kind = fakes.fake_search(q)
    stamp = datetime.now(timezone.utc).isoformat()
    canary = any(fakes.CANARY_PREFIX in str(r.get("memo", "")) for r in rows)
    served(request, what, kind=kind, sample=fakes.sample_rows(rows), category="sqli", canary=canary)
    return {"transactions": [{**r, "created_at": stamp} for r in rows]}


@app.post("/api/transactions/{transaction_id}/memo")
async def add_memo(transaction_id: str, request: Request) -> dict[str, Any]:
    memo = str((await body_of(request)).get("memo", ""))[:1000]
    ip = request.client.host if request.client else ""
    lines = f"{datetime.now(timezone.utc).isoformat()} INFO action=transaction_memo memo={memo}".splitlines()
    session_logs.setdefault(ip, []).extend(lines)  # forged lines land in this attacker's private copy only
    served(request, "forged log lines kept in a decoy log", kind="logs", sample="\n".join(lines)[:300], category="log_injection")
    return {"ok": True, "transaction_id": transaction_id, "memo": memo}


@app.get("/api/logs")
def logs(request: Request) -> dict[str, Any]:
    ip = request.client.host if request.client else ""
    served(request, "decoy activity log")
    return {"lines": (FAKE_LOG + session_logs.get(ip, []))[-15:]}


@app.post("/api/support/chat")
def support_chat(request: Request) -> dict[str, str]:
    reply, _ = fakes.fake_chat_reply()
    served(request, "decoy internal note with canary key", kind="prompt", sample=reply, category="prompt_injection", canary=True)
    return {"reply": reply}


@app.get("/api/statements/fetch")
def fetch_statement(request: Request, url: str = "") -> dict[str, Any]:
    served(request, "decoy statement fetch")
    return {"ok": True, "status_code": 200, "body": "Statement queued."}


@app.get("/admin")
def admin(request: Request) -> dict[str, Any]:
    staff = fakes.fake_staff()
    served(request, "decoy admin page with canary keys", kind="api_keys",
           sample=[{"name": s["name"], "value": s["api_key"]} for s in staff], canary=True)
    return {"staff": staff}


@app.get("/debug")
def debug(request: Request) -> dict[str, Any]:
    served(request, "decoy debug page")
    return {"debug": True, "client": "10.0.4.17", "version": "vulnbank-1.4.2"}


@app.get("/robots.txt")
def robots(request: Request) -> PlainTextResponse:
    served(request, "decoy robots.txt")
    return PlainTextResponse("User-agent: *\nDisallow: /admin\nDisallow: /api/internal/keys\nDisallow: /.env\n")


@app.get("/.env")
def dotenv(request: Request) -> PlainTextResponse:
    body = fakes.fake_env()
    served(request, "decoy .env with canary", kind="secrets", canary=True,
           sample=[{"name": k, "value": v} for k, v in (line.split("=", 1) for line in body.strip().splitlines())])
    return PlainTextResponse(body)


@app.get("/api/internal/keys")
def internal_keys(request: Request) -> dict[str, Any]:
    rows = [{"owner": "payments-service", "key": fakes.canary_token("ik1")},
            {"owner": "ops-admin", "key": fakes.canary_token("ik2")}]
    served(request, "decoy internal keys with canaries", kind="api_keys", canary=True,
           sample=[{"name": r["owner"], "value": r["key"]} for r in rows])
    return {"keys": rows}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def catch_all(path: str, request: Request) -> JSONResponse:
    served(request, "generic decoy 200")
    return JSONResponse({"ok": True})
