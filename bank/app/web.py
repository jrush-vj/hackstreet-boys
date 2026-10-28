from html import escape
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from bank.app.db import connect

router = APIRouter()
TEMPLATE_DIR = Path(__file__).parent / "templates"


def _template(name: str, **values: str) -> str:
    content = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    for key, value in values.items():
        content = content.replace(f"{{{{{key}}}}}", value)
    return content


def _customer(request: Request) -> dict[str, Any] | None:
    token = request.cookies.get("vulnbank_session")
    if not token:
        return None
    with connect() as connection:
        row = connection.execute(
            """
            SELECT c.id, c.name, c.email
            FROM sessions s JOIN customers c ON c.id = s.customer_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    return dict(row) if row is not None else None


def _navigation() -> str:
    links = (
        ("/accounts", "Accounts"),
        ("/transfer", "Transfer"),
        ("/search", "Search"),
        ("/support", "Support"),
        ("/statements", "Statements"),
    )
    return " ".join(
        f'<a href="{path}">{label}</a>' for path, label in links
    )


def render_page(
    request: Request,
    template_name: str,
    title: str,
    **values: str,
) -> HTMLResponse:
    customer = _customer(request)
    user = escape(customer["name"]) if customer else "Guest"
    content = _template(template_name, **values)
    document = _template(
        "layout.html",
        title=escape(title),
        user=user,
        navigation=_navigation(),
        content=content,
    )
    return HTMLResponse(document)


def login_page(request: Request, error: bool = False) -> HTMLResponse:
    return render_page(
        request,
        "login.html",
        "Sign in",
        error=(
            '<p class="notice error">Invalid email or password.</p>' if error else ""
        ),
    )


def transfer_result(request: Request, payload: dict[str, Any]) -> HTMLResponse:
    message = (
        f'<p class="notice success">Transfer of ${escape(str(payload["amount"]))} '
        f'from account {escape(str(payload["from_account_id"]))} to account '
        f'{escape(str(payload["to_account_id"]))} completed.</p>'
    )
    return render_page(request, "transfer.html", "Transfer", result=message)


def search_results(
    request: Request, query: str, transactions: list[dict[str, Any]]
) -> HTMLResponse:
    return render_page(
        request,
        "search_results.html",
        "Search",
        query=escape(query, quote=True),
        rows=transaction_rows(transactions),
    )


def transaction_rows(transactions: list[dict[str, Any]]) -> str:
    if not transactions:
        return '<tr><td colspan="5">No transactions found.</td></tr>'
    rows = []
    for transaction in transactions:
        transaction_id = int(transaction["id"])
        rows.append(
            "<tr>"
            f"<td>{transaction_id}</td>"
            f"<td>{escape(str(transaction.get('created_at', '')))}</td>"
            f"<td>{escape(str(transaction.get('description', '')))}</td>"
            f"<td>${escape(str(transaction.get('amount', '')))}</td>"
            "<td>"
            f'<form class="inline-form" action="/api/transactions/{transaction_id}/memo" method="post">'
            f'<label class="sr-only" for="memo-{transaction_id}">Memo for transaction {transaction_id}</label>'
            f'<input id="memo-{transaction_id}" name="memo" value="{escape(str(transaction.get("memo", "")), quote=True)}">'
            '<button type="submit">Save memo</button></form></td></tr>'
        )
    return "".join(rows)


def memo_result(request: Request, transaction_id: int) -> HTMLResponse:
    result = (
        f'<p class="notice success">Memo saved for transaction '
        f'{transaction_id}.</p>'
    )
    return render_page(request, "result.html", "Memo saved", result=result)


def support_result(request: Request, reply: str) -> HTMLResponse:
    return render_page(
        request,
        "support_result.html",
        "Support",
        reply=escape(reply),
    )


def statement_result(
    request: Request, url: str, result: dict[str, Any]
) -> HTMLResponse:
    body = escape(str(result.get("body", result.get("error", ""))))
    detail = (
        f'<p>Status: {escape(str(result.get("status_code", "")))}</p>'
        f"<pre>{body}</pre>"
    )
    return render_page(
        request,
        "statement_result.html",
        "Statements",
        url=escape(url, quote=True),
        result=detail,
    )


def is_html_request(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "").lower()


def signed_out_redirect() -> RedirectResponse:
    return RedirectResponse("/login", status_code=303)


@router.get("/", include_in_schema=False)
def home(request: Request) -> RedirectResponse:
    destination = "/accounts" if _customer(request) else "/login"
    return RedirectResponse(destination, status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login(request: Request) -> Response:
    return login_page(request, error=request.query_params.get("error") == "1")


@router.get("/logout", include_in_schema=False)
def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("vulnbank_session", path="/")
    return response


@router.get("/accounts", response_class=HTMLResponse)
def accounts(request: Request) -> Response:
    customer = _customer(request)
    if customer is None:
        return signed_out_redirect()
    with connect() as connection:
        account_rows = connection.execute(
            "SELECT id, account_number, balance FROM accounts WHERE customer_id = ? ORDER BY id",
            (customer["id"],),
        ).fetchall()
        account_ids = [int(row["id"]) for row in account_rows]
        transactions = []
        if account_ids:
            placeholders = ",".join("?" for _ in account_ids)
            transactions = [
                dict(row)
                for row in connection.execute(
                    f"""
                    SELECT id, account_id, kind, amount, description, memo, created_at
                    FROM transactions WHERE account_id IN ({placeholders})
                    ORDER BY id DESC LIMIT 20
                    """,
                    account_ids,
                ).fetchall()
            ]
    account_html = "".join(
        "<tr>"
        f'<td><a href="/api/accounts/{int(row["id"])}">{escape(str(row["account_number"]))}</a></td>'
        f'<td>{int(row["id"])}</td>'
        f'<td>${float(row["balance"]):,.2f}</td>'
        "</tr>"
        for row in account_rows
    )
    return render_page(
        request,
        "accounts.html",
        "Accounts",
        accounts=account_html,
        transactions=transaction_rows(transactions),
    )


@router.get("/transfer", response_class=HTMLResponse)
def transfer(request: Request) -> Response:
    if _customer(request) is None:
        return signed_out_redirect()
    return render_page(request, "transfer.html", "Transfer", result="")


@router.get("/search", response_class=HTMLResponse)
def search(request: Request) -> Response:
    if _customer(request) is None:
        return signed_out_redirect()
    return render_page(
        request,
        "search.html",
        "Search",
        query="",
    )


@router.get("/support", response_class=HTMLResponse)
def support(request: Request) -> Response:
    if _customer(request) is None:
        return signed_out_redirect()
    return render_page(request, "support.html", "Support")


@router.get("/statements", response_class=HTMLResponse)
def statements(request: Request) -> Response:
    if _customer(request) is None:
        return signed_out_redirect()
    return render_page(
        request,
        "statements.html",
        "Statements",
        result="",
        url="",
    )
