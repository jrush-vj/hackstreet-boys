"""P0 stub (Jerush). Akchhat builds VulnBank (real routes, seed data, weaknesses) in P1.
Routes follow docs/04-system-design.md section 8; response shapes are placeholders."""

from fastapi import FastAPI

from shared.config import settings  # noqa: F401  proves shared/ is wired in

app = FastAPI(title="bank")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/login")
def login():
    return {"token": "stub-token", "customer_id": 1}


@app.get("/api/accounts/{account_id}")
def account(account_id: int):
    return {"id": account_id, "customer_id": 1, "balance": 1000.0}


@app.post("/api/transfer")
def transfer():
    return {"ok": True, "transfer_id": 1}


@app.get("/api/transactions/search")
def search(q: str = ""):
    return []


@app.post("/api/transactions/{tx_id}/memo")
def memo(tx_id: int):
    return {"ok": True}


@app.post("/api/support/chat")
def chat():
    return {"reply": "stub support bot"}


@app.get("/api/statements/fetch")
def statement(url: str = ""):
    return {"ok": True}


@app.get("/admin")
def admin():
    return {"stub": "admin"}


@app.get("/debug")
def debug():
    return {"stub": "debug"}
