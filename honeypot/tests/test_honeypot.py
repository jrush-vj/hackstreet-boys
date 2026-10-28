"""docker compose run --rm honeypot pytest -q"""

import json

from fastapi.testclient import TestClient

from honeypot.app import fakes
from honeypot.app.main import app


class FakeRedis:
    def __init__(self):
        self.stream = []

    async def xadd(self, name, fields):
        self.stream.append((name, json.loads(fields["data"])))

    async def aclose(self):
        pass


def client_with_fake_redis():
    client = TestClient(app)
    client.__enter__()  # runs lifespan, then swap in the fake
    fake = FakeRedis()
    app.state.redis = fake
    return client, fake


def test_routes_mirror_bank_shapes_without_effects():
    client, _ = client_with_fake_redis()
    assert client.post("/api/login", json={"email": "a@b.test", "password": "x"}).json()["token"]
    assert client.get("/api/accounts/5").json()["account"]["id"] == 5
    assert client.post("/api/transfer", json={"from_account_id": 1, "to_account_id": 2, "amount": 9}).json()["ok"]
    assert "transactions" in client.get("/api/transactions/search", params={"q": "x"}).json()


def test_event_is_shared_schema_with_correlation_id():
    client, fake = client_with_fake_redis()
    client.get("/admin", headers={"X-Request-Id": "req-123"})
    stream, event = fake.stream[-1]
    assert stream == "events"
    assert event["source"] == "honeypot" and event["correlation_id"] == "req-123"
    assert event["details"]["route"] == "/admin" and event["details"]["action"] == "GET /admin"
    assert event["details"]["canary"] is True and event["details"]["kind"] == "api_keys"
    assert event["request"]["method"] == "GET" and event["id"] and event["ts"]


def test_health_emits_nothing():
    client, fake = client_with_fake_redis()
    client.get("/health")
    assert fake.stream == []


def test_union_probe_gets_canary_rows_and_details():
    client, fake = client_with_fake_redis()
    rows = client.get("/api/transactions/search", params={"q": "x' UNION SELECT key FROM api_keys--"}).json()["transactions"]
    assert any(fakes.CANARY_RE.search(str(r["memo"])) for r in rows)
    details = fake.stream[-1][1]["details"]
    assert details["kind"] == "api_keys" and details["category"] == "sqli" and details["canary"] is True
    assert details["sample"]


def test_odd_input_never_gets_a_tell_tale_error():
    client, _ = client_with_fake_redis()
    assert client.post("/api/accounts/not-a-number", content=b"{not json").status_code == 200
    assert client.post("/api/transfer", json=["unexpected", "list"]).json()["ok"] is True
    assert client.get("/.env").text.count(fakes.CANARY_PREFIX) == 1
