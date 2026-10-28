import asyncio
import json
import time

import httpx
from app import main as gateway_main
from fastapi.testclient import TestClient

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
        self.expirations = {}
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

    async def sismember(self, key, member):
        return member in self.values.get(key, set())

    async def sadd(self, key, member):
        self.values.setdefault(key, set()).add(member)

    async def hset(self, key, field, value):
        self.values.setdefault(key, {})[field] = value

    async def set(self, key, value, ex=None):
        self.values[key] = value
        self.expirations[key] = ex

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
    monkeypatch.setattr(
        gateway_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis
    )
    monkeypatch.setattr(
        gateway_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream
    )

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
    monkeypatch.setattr(
        gateway_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis
    )
    monkeypatch.setattr(
        gateway_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream
    )

    with TestClient(gateway_main.app) as client:
        login = client.post(
            "/api/login",
            json={"email": "customer1@example.test", "password": "password123"},
        )
        denied = client.get(
            "/api/accounts/22",
            headers={"Authorization": f"Bearer {login.json()['token']}"},
        )
        allowed = client.get(
            "/api/accounts/1",
            headers={"Authorization": f"Bearer {login.json()['token']}"},
        )

    assert login.status_code == 200
    assert len(redis.expirations) == 1
    assert set(redis.expirations.values()) == {gateway_main.SESSION_OWNER_TTL_SECONDS}
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
    monkeypatch.setattr(
        gateway_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis
    )
    monkeypatch.setattr(
        gateway_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream
    )

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
    assert (
        replay_request[2]["json"]["correlation_id"] == diverted.headers["X-Request-Id"]
    )
    emitted = [json.loads(values["data"]) for _, values in redis.events]
    assert [event["verdict"] for event in emitted] == ["SAFE", "DIVERT"]


def test_canary_reuse_is_denied_but_never_bans_the_ip(monkeypatch):
    canary_rule = Rule(id="canary-001", owasp="A07", match_type="regex", target="any",
                       pattern="vb_live_CANARY_[0-9a-f]{12}", action="DENY", source="pack",
                       description="Canary reuse")
    redis = FakeRedis([canary_rule])
    upstream = FakeHTTPClient()
    monkeypatch.setattr(gateway_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis)
    monkeypatch.setattr(gateway_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream)

    with TestClient(gateway_main.app) as client:
        caught = client.get("/api/accounts/12", headers={"authorization": "Bearer vb_live_CANARY_0123456789ab"})
        after = client.get("/api/accounts/12")  # same IP, clean request: still served (bans are display-only)

    assert caught.status_code == 403 and caught.json()["rule_id"] == "canary-001"
    assert after.status_code == 200 and after.headers["X-Verdict"] == "SAFE"


def test_upload_detection_only_for_archives_and_eicar():
    from app.main import looks_like_upload, ZIP_MAGIC
    assert looks_like_upload("application/zip", b"abc")
    assert looks_like_upload("text/plain", ZIP_MAGIC + b"rest")
    assert not looks_like_upload("text/plain", b"plain text, no archive")  # not an upload: no zip signature
    assert not looks_like_upload("application/json", b'{"a": 1}')
    assert not looks_like_upload("application/zip", b"")


def test_client_ip_trusts_cloudflare_header_only_from_a_private_peer():
    from app.main import client_ip
    assert client_ip({"cf-connecting-ip": "203.0.113.7"}, "172.18.0.1") == "203.0.113.7"  # via the tunnel
    assert client_ip({"cf-connecting-ip": "203.0.113.7"}, "8.8.8.8") == "8.8.8.8"  # spoofed from a public peer
    assert client_ip({"cf-connecting-ip": "not-an-ip"}, "172.18.0.1") == "172.18.0.1"
    assert client_ip({}, "127.0.0.1") == "127.0.0.1"
