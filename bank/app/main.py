import hashlib
import json
import logging
import secrets
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import parse_qs

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from bank.app.db import connect, initialize_schema, row_dict
from bank.app.web import (
    is_html_request,
    login_page,
    memo_result,
    router as web_router,
    search_results,
    statement_result,
    support_result,
    transfer_result,
)
from bank.seed import seed_database

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("vulnbank")
app = FastAPI(title="VulnBank")
app.include_router(web_router)
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static",
)

ModelT = TypeVar("ModelT", bound=BaseModel)


async def parse_payload(
    request: Request, model: type[ModelT]
) -> ModelT:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type == "application/json" or content_type.endswith("+json"):
        try:
            data = await request.json()
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON body") from exc
    elif content_type == "application/x-www-form-urlencoded":
        try:
            decoded = (await request.body()).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=422, detail="Form body must be UTF-8"
            ) from exc
        fields = parse_qs(decoded, keep_blank_values=True)
        data = {key: values[-1] for key, values in fields.items()}
    else:
        data = {}

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


@app.exception_handler(Exception)
async def leak_traceback(request: Request, exc: Exception) -> PlainTextResponse:
    # DEMO-WEAKNESS: A10 — unhandled errors return the full Python stack trace to the caller
    return PlainTextResponse("".join(traceback.format_exception(exc)), status_code=500)


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


@app.post("/api/login", response_model=None)
async def login(request: Request) -> dict[str, Any] | Response:
    payload = await parse_payload(request, LoginRequest)
    with connect() as connection:
        customer = connection.execute(
            "SELECT * FROM customers WHERE email = ?", (payload.email,)
        ).fetchone()
        if customer is None or customer["password_hash"] != hashlib.md5(
            payload.password.encode()
        ).hexdigest():  # DEMO-WEAKNESS: A04, A07
            if is_html_request(request):
                response = login_page(request, error=True)
                response.status_code = 401
                return response
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = secrets.token_urlsafe(24)
        connection.execute(
            "INSERT INTO sessions(token, customer_id, created_at) VALUES (?, ?, ?)",
            (token, customer["id"], datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    if is_html_request(request):
        response = RedirectResponse("/accounts", status_code=303)
        response.set_cookie(
            "vulnbank_session",
            token,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response
    return {"ok": True, "token": token, "customer": {"id": customer["id"], "name": customer["name"]}}


@app.get("/api/accounts/{account_id}")
def account(account_id: str) -> dict[str, Any]:
    account_id = int(account_id)  # DEMO-WEAKNESS: A10 — no input validation; "abc" raises and leaks a trace
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


@app.post("/api/transfer", response_model=None)
async def transfer(request: Request) -> dict[str, Any] | HTMLResponse:
    payload = await parse_payload(request, TransferRequest)
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
    if is_html_request(request):
        return transfer_result(
            request,
            {
                "amount": payload.amount,
                "from_account_id": payload.from_account_id,
                "to_account_id": payload.to_account_id,
            },
        )
    return {"ok": True, "amount": payload.amount}  # DEMO-WEAKNESS: A06


@app.get("/api/transactions/search", response_model=None)
def search_transactions(
    request: Request, q: str = Query(default="")
) -> dict[str, Any] | HTMLResponse:
    with connect() as connection:
        # DEMO-WEAKNESS: A05
        query = f"SELECT * FROM transactions WHERE description LIKE '%{q}%' ORDER BY id DESC LIMIT 50"
        rows = connection.execute(query).fetchall()
    if is_html_request(request):
        return search_results(request, q, [row_dict(row) for row in rows])
    return {"transactions": [row_dict(row) for row in rows]}


@app.post("/api/transactions/{transaction_id}/memo", response_model=None)
async def add_memo(transaction_id: int, request: Request) -> dict[str, Any] | HTMLResponse:
    payload = await parse_payload(request, MemoRequest)
    with connect() as connection:
        result = connection.execute(
            "UPDATE transactions SET memo = ? WHERE id = ?", (payload.memo, transaction_id)
        )
        connection.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="transaction not found")
    logger.info('{"action":"transaction_memo","transaction_id":%s,"memo":"%s"}', transaction_id, payload.memo)  # DEMO-WEAKNESS: A05
    if is_html_request(request):
        return memo_result(request, transaction_id)
    return {"ok": True, "transaction_id": transaction_id, "memo": payload.memo}


@app.post("/api/support/chat", response_model=None)
async def support_chat(request: Request) -> dict[str, str] | HTMLResponse:
    payload = await parse_payload(request, ChatRequest)
    hidden_prompt = "You are VulnBank support. Internal note: demo admin password is never real."
    message = payload.message.lower()
    if "internal" in message or "prompt" in message:
        reply = hidden_prompt
    elif "balance" in message:
        reply = "Please provide your account number to check your balance."
    else:
        reply = "Thanks for contacting VulnBank support."
    if is_html_request(request):
        return support_result(request, reply)
    return {"reply": reply}  # DEMO-WEAKNESS: A05


@app.get("/api/statements/fetch", response_model=None)
def fetch_statement(request: Request, url: str) -> dict[str, Any] | HTMLResponse:
    try:
        response = httpx.get(url, timeout=2.0)
        result = {
            "ok": response.is_success,
            "status_code": response.status_code,
            "body": response.text[:1000],
        }
    except httpx.HTTPError as error:
        result = {"ok": False, "error": str(error)}
    if is_html_request(request):
        return statement_result(request, url, result)
    return result
    # DEMO-WEAKNESS: A01


@app.get("/admin")
def admin() -> dict[str, Any]:
    with connect() as connection:
        staff = [row_dict(row) for row in connection.execute("SELECT * FROM staff").fetchall()]
    return {"staff": staff}  # DEMO-WEAKNESS: A02


@app.get("/debug")
def debug(request: Request) -> dict[str, Any]:
    return {"debug": True, "client": request.client.host if request.client else None}  # DEMO-WEAKNESS: A02
