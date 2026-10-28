import asyncio
import json

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

    async def ping(self):
        return True

    async def hgetall(self, key):
        assert key == "rules:active"
        return {rule.id: rule.model_dump_json() for rule in self.rules}

    def pubsub(self):
        return FakePubSub()

    async def xadd(self, stream, values):
        self.events.append((stream, values))

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
