"""docker compose run --rm bank pytest -q  (uses a throwaway SQLite file, not the demo DB)"""

from bank.app.db import connect


def test_seed_counts(client):
    with connect() as c:
        counts = {t: c.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                  for t in ("customers", "accounts", "transactions", "staff")}
    assert counts == {"customers": 50, "accounts": 120, "transactions": 2000, "staff": 3}


def test_login_with_seed_credentials(client):
    r = client.post("/api/login", json={"email": "customer1@example.test", "password": "password123"})
    assert r.status_code == 200 and r.json()["token"]
    bad = client.post("/api/login", json={"email": "customer1@example.test", "password": "nope"})
    assert bad.status_code == 401


def test_account_lookup_returns_owner(client):
    account = client.get("/api/accounts/1").json()["account"]
    assert account["customer_id"] == 1  # the gateway's A01 owner check reads this field


def test_transfer_moves_money(client):
    before = client.get("/api/accounts/2").json()["account"]["balance"]
    r = client.post("/api/transfer", json={"from_account_id": 2, "to_account_id": 3, "amount": 1.0})
    assert r.status_code == 200
    assert client.get("/api/accounts/2").json()["account"]["balance"] == round(before - 1.0, 2)


def test_search_and_memo(client):
    assert isinstance(client.get("/api/transactions/search", params={"q": "a"}).json()["transactions"], list)
    assert client.post("/api/transactions/1/memo", json={"memo": "note"}).json()["ok"] is True


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
