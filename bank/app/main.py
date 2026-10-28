import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from bank.app.db import connect, initialize_schema, row_dict
from bank.seed import seed_database

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("vulnbank")
app = FastAPI(title="VulnBank")


class LoginRequest(BaseModel):
    email: str
    password: str


class TransferRequest(BaseModel):
    from_account_id: int
    to_account_id: int
    amount: float = Field(gt=0)


class MemoRequest(BaseModel):
    memo: str


class ChatRequest(BaseModel):
    message: str


@app.on_event("startup")
def startup() -> None:
    seed_database()
    with connect() as connection:
        initialize_schema(connection)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    with connect() as connection:
        customer = connection.execute(
            "SELECT * FROM customers WHERE email = ?", (payload.email,)
        ).fetchone()
        if customer is None or customer["password_hash"] != hashlib.md5(
            payload.password.encode()
        ).hexdigest():  # DEMO-WEAKNESS: A04, A07
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = secrets.token_urlsafe(24)
        connection.execute(
            "INSERT INTO sessions(token, customer_id, created_at) VALUES (?, ?, ?)",
            (token, customer["id"], datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    return {"ok": True, "token": token, "customer": {"id": customer["id"], "name": customer["name"]}}


@app.get("/api/accounts/{account_id}")
def account(account_id: int) -> dict[str, Any]:
    with connect() as connection:
        result = connection.execute(
            """
            SELECT a.id, a.account_number, a.balance, c.id AS customer_id, c.name AS customer_name
            FROM accounts a JOIN customers c ON c.id = a.customer_id WHERE a.id = ?
            """,
            (account_id,),
        ).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="account not found")
    return {"account": row_dict(result)}  # DEMO-WEAKNESS: A01


@app.post("/api/transfer")
def transfer(payload: TransferRequest) -> dict[str, Any]:
    with connect() as connection:
        source = connection.execute("SELECT * FROM accounts WHERE id = ?", (payload.from_account_id,)).fetchone()
        target = connection.execute("SELECT * FROM accounts WHERE id = ?", (payload.to_account_id,)).fetchone()
        if source is None or target is None:
            raise HTTPException(status_code=404, detail="account not found")
        if source["balance"] < payload.amount:
            raise HTTPException(status_code=400, detail="insufficient funds")
        connection.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (payload.amount, source["id"]))
        connection.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (payload.amount, target["id"]))
        connection.commit()
    return {"ok": True, "amount": payload.amount}  # DEMO-WEAKNESS: A06


@app.get("/api/transactions/search")
def search_transactions(q: str = Query(default="")) -> dict[str, Any]:
    with connect() as connection:
        # DEMO-WEAKNESS: A05
        query = f"SELECT * FROM transactions WHERE description LIKE '%{q}%' ORDER BY id DESC LIMIT 50"
        rows = connection.execute(query).fetchall()
    return {"transactions": [row_dict(row) for row in rows]}


@app.post("/api/transactions/{transaction_id}/memo")
def add_memo(transaction_id: int, payload: MemoRequest) -> dict[str, Any]:
    with connect() as connection:
        result = connection.execute(
            "UPDATE transactions SET memo = ? WHERE id = ?", (payload.memo, transaction_id)
        )
        connection.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="transaction not found")
    logger.info('{"action":"transaction_memo","transaction_id":%s,"memo":"%s"}', transaction_id, payload.memo)  # DEMO-WEAKNESS: A05
    return {"ok": True, "transaction_id": transaction_id, "memo": payload.memo}


@app.post("/api/support/chat")
def support_chat(payload: ChatRequest) -> dict[str, str]:
    hidden_prompt = "You are VulnBank support. Internal note: demo admin password is never real."
    message = payload.message.lower()
    if "internal" in message or "prompt" in message:
        reply = hidden_prompt
    elif "balance" in message:
        reply = "Please provide your account number to check your balance."
    else:
        reply = "Thanks for contacting VulnBank support."
    return {"reply": reply}  # DEMO-WEAKNESS: A05


@app.get("/api/statements/fetch")
def fetch_statement(url: str) -> dict[str, Any]:
    try:
        response = httpx.get(url, timeout=2.0)
        return {"ok": response.is_success, "status_code": response.status_code, "body": response.text[:1000]}
    except httpx.HTTPError as error:
        return {"ok": False, "error": str(error)}
    # DEMO-WEAKNESS: A01


@app.get("/admin")
def admin() -> dict[str, Any]:
    with connect() as connection:
        staff = [row_dict(row) for row in connection.execute("SELECT * FROM staff").fetchall()]
    return {"staff": staff}  # DEMO-WEAKNESS: A02


@app.get("/debug")
def debug(request: Request) -> dict[str, Any]:
    return {"debug": True, "client": request.client.host if request.client else None}  # DEMO-WEAKNESS: A02
