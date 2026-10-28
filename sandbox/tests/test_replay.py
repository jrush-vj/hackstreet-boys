import json

import httpx
from app import main as sandbox_main
from fastapi.testclient import TestClient


class FakeRedis:
    def __init__(self):
        self.events = []

    async def ping(self):
        return True

    async def xadd(self, stream, values):
        self.events.append((stream, values))

    async def aclose(self):
        pass


class FakeHTTPClient:
    def __init__(self, *args, **kwargs):
        self.requests = []
        self.response = httpx.Response(500, text="Internal Server Error")

    async def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        return self.response

    async def aclose(self):
        pass


def test_replay_calls_only_configured_sandbox_bank_and_emits_event(monkeypatch):
    redis = FakeRedis()
    upstream = FakeHTTPClient()
    monkeypatch.setattr(
        sandbox_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis
    )
    monkeypatch.setattr(
        sandbox_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream
    )

    with TestClient(sandbox_main.app) as client:
        response = client.post(
            "/replay",
            json={
                "correlation_id": "gateway-request-1",
                "method": "POST",
                "path": "/api/transactions/12/memo",
                "query": "",
                "headers": {"content-type": "application/json"},
                "body_b64": "eyJtZW1vIjoidGVzdCJ9",
            },
        )

    assert response.status_code == 202
    assert response.json() == {
        "accepted": True,
        "correlation_id": "gateway-request-1",
    }
    assert upstream.requests[0][1].startswith(sandbox_main.settings.bank_sandbox_url)
    emitted = json.loads(redis.events[0][1]["data"])
    assert emitted["source"] == "sandbox"
    assert emitted["correlation_id"] == "gateway-request-1"
    assert emitted["details"]["status"] == 500
    assert emitted["details"]["error"] is None
    assert isinstance(emitted["details"]["latency_ms"], int)
    assert emitted["details"]["stack_trace_leaked"] is False


def test_replay_flags_python_traceback_only_for_internal_server_errors(monkeypatch):
    redis = FakeRedis()
    upstream = FakeHTTPClient()
    upstream.response = httpx.Response(
        500,
        text=(
            "Traceback (most recent call last):\n"
            '  File "/app/bank.py", line 42, in transfer\n'
            "    raise ValueError('invalid amount')\n"
            "ValueError: invalid amount\n"
        ),
    )
    monkeypatch.setattr(
        sandbox_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis
    )
    monkeypatch.setattr(
        sandbox_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream
    )

    with TestClient(sandbox_main.app) as client:
        response = client.post(
            "/replay",
            json={
                "correlation_id": "traceback-leak",
                "method": "POST",
                "path": "/api/transfer",
                "body_b64": "",
            },
        )

    assert response.status_code == 202
    emitted = json.loads(redis.events[0][1]["data"])
    assert emitted["details"]["status"] == 500
    assert emitted["details"]["stack_trace_leaked"] is True


def test_replay_does_not_flag_a_traceback_body_from_non_500_response(monkeypatch):
    redis = FakeRedis()
    upstream = FakeHTTPClient()
    upstream.response = httpx.Response(
        400,
        text='Traceback (most recent call last):\n  File "/app/bank.py", line 42',
    )
    monkeypatch.setattr(
        sandbox_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis
    )
    monkeypatch.setattr(
        sandbox_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream
    )

    with TestClient(sandbox_main.app) as client:
        response = client.post(
            "/replay",
            json={
                "correlation_id": "client-error",
                "method": "POST",
                "path": "/api/transfer",
                "body_b64": "",
            },
        )

    assert response.status_code == 202
    emitted = json.loads(redis.events[0][1]["data"])
    assert emitted["details"]["stack_trace_leaked"] is False


def test_replay_records_connection_errors_and_rejects_invalid_base64(monkeypatch):
    class FailingHTTPClient(FakeHTTPClient):
        async def request(self, method, url, **kwargs):
            raise httpx.ConnectError(
                "sandbox bank unavailable", request=httpx.Request(method, url)
            )

    redis = FakeRedis()
    upstream = FailingHTTPClient()
    monkeypatch.setattr(
        sandbox_main.redis_asyncio, "from_url", lambda *args, **kwargs: redis
    )
    monkeypatch.setattr(
        sandbox_main.httpx, "AsyncClient", lambda *args, **kwargs: upstream
    )

    with TestClient(sandbox_main.app) as client:
        rejected = client.post(
            "/replay",
            json={
                "correlation_id": "bad-base64",
                "method": "GET",
                "path": "/api/accounts/1",
                "body_b64": "not-base64",
            },
        )
        response = client.post(
            "/replay",
            json={
                "correlation_id": "connection-error",
                "method": "GET",
                "path": "/api/accounts/1",
            },
        )

    assert rejected.status_code == 422
    assert response.status_code == 202
    emitted = json.loads(redis.events[0][1]["data"])
    assert emitted["correlation_id"] == "connection-error"
    assert emitted["details"]["status"] == 0
    assert emitted["details"]["error"] == "sandbox bank unavailable"
