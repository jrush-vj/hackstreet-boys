import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from pydantic import BaseModel

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


app = FastAPI(title="VulnBank Honeypot", lifespan=lifespan)


class LoginRequest(BaseModel):
    email: str
    password: str


class TransferRequest(BaseModel):
    from_account_id: int
    to_account_id: int
    amount: float


class MemoRequest(BaseModel):
    memo: str


class ChatRequest(BaseModel):
    message: str


async def emit_event(request: Request, action: str) -> None:
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
        ),
        details={"route": request.url.path, "action": action},
    )
    try:
        await emit(request.app.state.redis, event)
    except Exception as error:  # never fail the attacker's response because Redis blipped
        logger.error("honeypot event emission failed: %s", error)


@app.middleware("http")
async def event_middleware(request: Request, call_next):
    response = await call_next(request)
    if request.url.path != "/health":  # Docker healthchecks every 10 s are not attacker traffic
        await emit_event(request, f"{request.method} {request.url.path}")
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    return {"ok": True, "token": "honeypot-token", "customer": {"id": 1, "name": "Demo Customer"}}


@app.get("/api/accounts/{account_id}")
def account(account_id: int) -> dict[str, Any]:
    return {
        "account": {
            "id": account_id,
            "account_number": f"TRAP-{account_id:08d}",
            "balance": 5000.0,
            "customer_id": 1,
            "customer_name": "Demo Customer",
        }
    }


@app.post("/api/transfer")
def transfer(payload: TransferRequest) -> dict[str, Any]:
    return {"ok": True, "amount": payload.amount}


@app.get("/api/transactions/search")
def search_transactions(q: str = "") -> dict[str, Any]:
    return {
        "transactions": [
            {
                "id": 1,
                "account_id": 1,
                "kind": "debit",
                "amount": 10.0,
                "description": f"matching {q}",
                "memo": "",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
    }


@app.post("/api/transactions/{transaction_id}/memo")
def add_memo(transaction_id: int, payload: MemoRequest) -> dict[str, Any]:
    return {"ok": True, "transaction_id": transaction_id, "memo": payload.memo}


@app.post("/api/support/chat")
def support_chat(payload: ChatRequest) -> dict[str, str]:
    return {"reply": "Thanks for contacting VulnBank support."}


@app.get("/api/statements/fetch")
def fetch_statement(url: str) -> dict[str, Any]:
    return {"ok": True, "status_code": 200, "body": "Statement request recorded."}


@app.get("/admin")
def admin() -> dict[str, Any]:
    return {
        "staff": [
            {
                "id": 1,
                "name": "Demo Admin",
                "email": "admin@example.test",
                "role": "admin",
            }
        ]
    }


@app.get("/debug")
def debug() -> dict[str, Any]:
    return {"debug": True, "service": "honeypot"}
