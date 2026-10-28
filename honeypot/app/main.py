import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("honeypot")
app = FastAPI(title="VulnBank Honeypot")


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


def emit_event(request: Request, action: str) -> None:
    event = {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": "honeypot",
        "correlation_id": request.headers.get("x-request-id", ""),
        "request": {"method": request.method, "path": request.url.path, "ip": request.client.host if request.client else ""},
        "details": {"route": request.url.path, "action": action},
    }
    payload = json.dumps(event)
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        try:
            import redis

            redis.Redis.from_url(redis_url).xadd("events", {"data": payload})
            return
        except Exception as error:
            logger.error("honeypot event emission failed: %s", error)
    logger.info(payload)


@app.middleware("http")
async def event_middleware(request: Request, call_next):
    response = await call_next(request)
    emit_event(request, f"{request.method} {request.url.path}")
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
