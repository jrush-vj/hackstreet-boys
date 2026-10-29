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
    # benign only: malicious-but-SAFE items (e.g. the first logins of an A07 burst) may legitimately get 401
    items = [c for c in by_verdict("SAFE") if c["label"] == "benign"]
    assert items, "corpus has no benign SAFE items"
    for item in items:
        r = send(item)
        assert r.headers.get("X-Verdict") == "SAFE", item["id"]
        assert "stub" not in r.text, f"{item['id']}: bank or gateway is still the P0 stub"
        # a SAFE request must actually work; 4xx here means corpus and bank disagree on the body
        assert r.status_code < 400, f"{item['id']}: bank returned {r.status_code}: {r.text[:150]}"


def test_pack_rules_divert_a05_on_first_run():
    # unknown on first run: the first A05 item DIVERTs (honeypot + sandbox). Later items in this loop may already
    # match a rule the learner wrote from the earlier ones, so those can be DENY: that is the intended behaviour.
    items = [c for c in by_verdict("DIVERT") if c["owasp"] == "A05"]
    for n, item in enumerate(items):
        r = send(item)
        expected = {"DIVERT"} if n == 0 else {"DIVERT", "DENY"}
        assert r.headers["X-Verdict"] in expected, item["id"]


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
    send(by_verdict("SAFE")[0])
    send([c for c in by_verdict("DENY") if c["owasp"] == "A01"][0])
    send([c for c in by_verdict("DIVERT") if c["owasp"] == "A05"][0])
    time.sleep(1.5)  # events reach the analyst
    stats = httpx.get(f"{ANALYST}/api/stats").json()
    assert stats["totals"]["SAFE"] > 0 and stats["totals"]["DENY"] > 0 and stats["totals"]["DIVERT"] > 0
    assert stats["owasp"]["A05"]["DIVERT"] > 0
