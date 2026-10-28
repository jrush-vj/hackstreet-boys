"""G0: every container healthy, every contract endpoint answers with the right shape.
Run against `docker compose up` in dev (override ports): pytest tests/e2e -q"""

import json
import subprocess

import httpx
import pytest

SERVICES = ["gateway", "sandbox", "bank", "bank-sandbox", "honeypot", "analyst",
            "runner", "mock-llm", "dashboard", "redis", "postgres"]
HTTP = {"gateway": 8000, "bank": 8001, "honeypot": 8002, "sandbox": 8003,
        "analyst": 8004, "runner": 8005, "dashboard": 3000}


def test_all_containers_healthy():
    out = subprocess.run(["docker", "compose", "ps", "--format", "json"],
                         capture_output=True, text=True, check=True).stdout
    # compose prints one JSON object per line
    health = {c["Service"]: c.get("Health") for c in map(json.loads, out.splitlines())}
    assert {s: health.get(s) for s in SERVICES} == {s: "healthy" for s in SERVICES}


@pytest.mark.parametrize("svc", HTTP)
def test_health(svc):
    assert httpx.get(f"http://localhost:{HTTP[svc]}/health").json() == {"status": "ok"}


def test_gateway_headers():
    r = httpx.get("http://localhost:8000/api/accounts/1")
    assert r.headers["X-Verdict"] in {"SAFE", "DIVERT", "DENY"}
    assert r.headers["X-Request-Id"]


def test_sandbox_replay_accepted():
    r = httpx.post("http://localhost:8003/replay", json={"correlation_id": "x", "method": "GET",
                   "path": "/", "query": "", "headers": {}, "body_b64": ""})
    assert r.status_code == 202


def test_analyst_contracts_via_dashboard_proxy():
    base = "http://localhost:3000"
    stats = httpx.get(f"{base}/api/stats").json()
    assert set(stats["totals"]) == {"SAFE", "DIVERT", "DENY"}
    assert len(stats["owasp"]) == 10
    assert isinstance(httpx.get(f"{base}/api/events").json(), list)
    assert isinstance(httpx.get(f"{base}/api/rules").json(), list)
    assert isinstance(httpx.get(f"{base}/api/timers").json(), list)
    assert "run_id" in httpx.post(f"{base}/api/scenario/run", json={"scenario": "full"}).json()


def test_runner_contract():
    run_id = httpx.post("http://localhost:8005/run", json={"scenario": "full"}).json()["run_id"]
    assert httpx.get(f"http://localhost:8005/runs/{run_id}").json()["run_id"] == run_id
