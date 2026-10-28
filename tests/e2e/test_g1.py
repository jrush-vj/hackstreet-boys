"""G1 (docs/05-phases-and-gates.md): SAFE path returns real bank data, the 3 A05 packs DENY,
every request is persisted. Needs Abhinav's gateway + packs + corpus and Akchhat's bank.
Run against `docker compose up` in dev: pytest tests/e2e -q"""

import json
import time
from pathlib import Path

import httpx
import pytest

GATEWAY = "http://localhost:8000"
ANALYST = "http://localhost:8004"
CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "corpus.jsonl"
PACKS = ("sqli-", "prompt-", "logi-")


def corpus() -> list[dict]:
    assert CORPUS.exists(), f"missing {CORPUS} (Abhinav, P1)"
    return [json.loads(line) for line in CORPUS.read_text().splitlines() if line.strip()]


def send(item: dict) -> httpx.Response:
    assert GATEWAY.startswith(("http://localhost:8000", "http://gateway:8000"))  # AGENTS.md section 7
    return httpx.request(item["method"], GATEWAY + item["path"], params=item.get("query") or None,
                         headers=item.get("headers") or {}, json=item.get("body"))


def by_verdict(verdict: str) -> list[dict]:
    return [c for c in corpus() if c["expected_verdict"] == verdict]


def test_safe_requests_reach_the_real_bank():
    items = by_verdict("SAFE")
    assert items, "corpus has no SAFE items"
    for item in items:
        r = send(item)
        assert r.headers.get("X-Verdict") == "SAFE", item["id"]
        assert "stub" not in r.text, f"{item['id']}: bank or gateway is still the P0 stub"


def test_pack_rules_deny_with_a05():
    hit_packs = set()
    for item in [c for c in by_verdict("DENY") if c["owasp"] == "A05"]:
        r = send(item)
        assert r.status_code == 403, item["id"]
        body = r.json()
        assert body["verdict"] == "DENY" and body["owasp"] == "A05", item["id"]
        assert body["request_id"] == r.headers["X-Request-Id"], item["id"]
        hit_packs.update(p for p in PACKS if body["rule_id"].startswith(p))
    assert hit_packs == set(PACKS), f"packs never hit: {set(PACKS) - hit_packs}"


@pytest.mark.parametrize("verdict", ["SAFE", "DENY"])
def test_requests_are_persisted(verdict):
    r = send(by_verdict(verdict)[0])
    rid = r.headers["X-Request-Id"]
    end = time.time() + 5
    while time.time() < end:
        events = httpx.get(f"{ANALYST}/api/events", params={"limit": 200}).json()
        mine = [e for e in events if e["correlation_id"] == rid and e["source"] == "gateway"]
        if mine:
            assert mine[0]["verdict"] == verdict
            return
        time.sleep(0.3)
    pytest.fail(f"no gateway event persisted for {rid}")


def test_stats_count_verdicts():
    stats = httpx.get(f"{ANALYST}/api/stats").json()
    assert stats["totals"]["SAFE"] > 0 and stats["totals"]["DENY"] > 0
    assert stats["owasp"]["A05"]["DENY"] > 0
