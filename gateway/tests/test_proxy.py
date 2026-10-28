import asyncio
import json
import time

import httpx
from fastapi.testclient import TestClient

from app import main as gateway_main
from shared.schemas import Rule


class FakePubSub:
    async def subscribe(self, channel):
        assert channel == "rules:updated"

    async def listen(self):
        await asyncio.Event().wait()
        yield {}

    async def aclose(self):
        pass


class FakeRedis:
    def __init__(self, rules):
        self.rules = rules
        self.events = []
        self.values = {}
        self.counters = {}

    async def ping(self):
        return True

    async def hgetall(self, key):
        assert key == "rules:active"
        return {rule.id: rule.model_dump_json() for rule in self.rules}

    def pubsub(self):
        return FakePubSub()

    async def xadd(self, stream, values):
        self.events.append((stream, values))

    async def set(self, key, value):
        self.values[key] = value

    async def get(self, key):
        return self.values.get(key)

    async def eval(self, script, key_count, key, window):
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def aclose(self):
        pass


class FakeHTTPClient:
    def __init__(self, *args, **kwargs):
        self.requests = []

    async def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'{"account_id":12}',
        )

    async def post(self, url, **kwargs):
        self.requests.append(("POST", url, kwargs))
        return httpx.Response(202)

    async def aclose(self):
        pass


def test_proxy_and_deny_contract(monkeypatch):
    deny_rule = Rule(
        id="sqli-001",
        owasp="A05",
        match_type="regex",
        target="query",
        pattern="malicious",
        action="DENY",
        source="pack",
        description="Test deny rule",
    )
    redis = FakeRedis([deny_rule])
    upstream = FakeHTTPClient()
    monkeypatch.setattr(gateway_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis)
    monkeypatch.setattr(gateway_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream)

    with TestClient(gateway_main.app) as client:
        safe = client.get("/api/accounts/12", headers={"X-Request-Id": "request-123"})
        denied = client.get("/api/transactions/search?q=malicious")

    assert safe.status_code == 200
    assert safe.json() == {"account_id": 12}
    assert safe.headers["X-Verdict"] == "SAFE"
    assert safe.headers["X-Request-Id"] == "request-123"
    assert upstream.requests[0][1].endswith("/api/accounts/12")

    assert denied.status_code == 403
    assert denied.json() == {
        "verdict": "DENY",
        "rule_id": "sqli-001",
        "owasp": "A05",
        "request_id": denied.headers["X-Request-Id"],
    }
    assert denied.headers["X-Verdict"] == "DENY"
    assert len(upstream.requests) == 1

    emitted = [json.loads(values["data"]) for _, values in redis.events]
    assert [event["verdict"] for event in emitted] == ["SAFE", "DENY"]


def test_login_session_owner_blocks_another_customers_account(monkeypatch):
    class BankHTTPClient(FakeHTTPClient):
        async def request(self, method, url, **kwargs):
            self.requests.append((method, url, kwargs))
            if url.endswith("/api/login"):
                return httpx.Response(
                    200,
                    json={"token": "session-secret", "customer": {"id": 1}},
                )
            if url.endswith("/api/accounts/22"):
                return httpx.Response(
                    200,
                    json={"account": {"id": 22, "customer_id": 22}},
                )
            return httpx.Response(
                200,
                json={"account": {"id": 1, "customer_id": 1}},
            )

    redis = FakeRedis([])
    upstream = BankHTTPClient()
    monkeypatch.setattr(gateway_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis)
    monkeypatch.setattr(gateway_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream)

    with TestClient(gateway_main.app) as client:
        login = client.post("/api/login", json={"email": "customer1@example.test", "password": "password123"})
        denied = client.get(
            "/api/accounts/22",
            headers={"Authorization": f"Bearer {login.json()['token']}"},
        )
        allowed = client.get(
            "/api/accounts/1",
            headers={"Authorization": f"Bearer {login.json()['token']}"},
        )

    assert login.status_code == 200
    assert denied.status_code == 403
    assert denied.json()["owasp"] == "A01"
    assert denied.headers["X-Verdict"] == "DENY"
    assert allowed.status_code == 200
    assert allowed.headers["X-Verdict"] == "SAFE"


def test_divert_uses_honeypot_and_schedules_correlated_sandbox_replay(monkeypatch):
    transfer_rule = Rule(
        id="rate-002",
        owasp="A06",
        match_type="rate",
        pattern="/api/transfer",
        params={"key": "account", "limit": 1, "window_s": 60},
        action="DIVERT",
        source="pack",
        description="Test transfer burst",
    )
    redis = FakeRedis([transfer_rule])
    upstream = FakeHTTPClient()
    monkeypatch.setattr(gateway_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis)
    monkeypatch.setattr(gateway_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream)

    with TestClient(gateway_main.app) as client:
        safe = client.post(
            "/api/transfer",
            json={"from_account_id": 12, "to_account_id": 13, "amount": 1},
        )
        diverted = client.post(
            "/api/transfer",
            json={"from_account_id": 12, "to_account_id": 13, "amount": 1},
        )
        for _ in range(50):
            if any(url.endswith("/replay") for _, url, _ in upstream.requests):
                break
            time.sleep(0.01)

    assert safe.headers["X-Verdict"] == "SAFE"
    assert diverted.headers["X-Verdict"] == "DIVERT"
    assert diverted.status_code == 200
    honeypot_request = next(
        call
        for call in upstream.requests
        if "/api/transfer" in call[1]
        and call[1].startswith(gateway_main.settings.honeypot_url)
    )
    assert honeypot_request[1].startswith(gateway_main.settings.honeypot_url)
    replay_request = next(
        call for call in upstream.requests if call[1].endswith("/replay")
    )
    assert replay_request[2]["json"]["correlation_id"] == diverted.headers["X-Request-Id"]
    emitted = [json.loads(values["data"]) for _, values in redis.events]
    assert [event["verdict"] for event in emitted] == ["SAFE", "DIVERT"]
