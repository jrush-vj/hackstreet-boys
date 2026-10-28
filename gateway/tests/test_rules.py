import asyncio
import json
from pathlib import Path

import yaml

from app.anomaly import score_request
from app.engine import (
    RequestContext,
    RuleEngine,
)
from app.main import listen_for_rule_updates, reload_active_rules
from shared.schemas import Rule

ROOT = Path(__file__).resolve().parents[1]
PACK_DIR = ROOT / "rules" / "packs"
CORPUS_PATH = ROOT / "tests" / "corpus" / "corpus.jsonl"
if not CORPUS_PATH.exists():
    CORPUS_PATH = ROOT.parent / "tests" / "corpus" / "corpus.jsonl"
P1_PACKS = {"sqli.yaml", "prompt.yaml", "logi.yaml"}


def load_pack_rules() -> list[Rule]:
    rules = []
    for path in sorted(PACK_DIR.glob("*.yaml")):
        if path.name not in P1_PACKS:
            continue
        for item in yaml.safe_load(path.read_text()):
            rules.append(Rule.model_validate({**item, "source": "pack"}))
    return rules


def load_all_pack_rules() -> list[Rule]:
    rules = []
    for path in sorted(PACK_DIR.glob("*.yaml")):
        for item in yaml.safe_load(path.read_text()):
            rules.append(Rule.model_validate({**item, "source": "pack"}))
    return rules


def load_corpus() -> list[dict]:
    return [
        json.loads(line)
        for line in CORPUS_PATH.read_text().splitlines()
        if line.strip()
    ]


def make_context(item: dict) -> RequestContext:
    body = item.get("body")
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    return RequestContext(
        path=item["path"],
        query=item.get("query", ""),
        headers=item.get("headers", {}),
        body=body or "",
    )


def test_each_pack_rule_has_a_corpus_match_and_benign_stays_safe():
    rules = load_pack_rules()
    corpus = load_corpus()
    engine = RuleEngine()
    engine.replace_rules(rules)
    matching_rule_ids = set()

    corpus = [item for item in corpus if item["id"] <= "c-0040"]
    assert len(corpus) == 40
    assert sum(item["label"] == "benign" for item in corpus) == 20
    assert sum(item["label"] == "malicious" for item in corpus) == 20

    for item in corpus:
        matched = asyncio.run(engine.evaluate(make_context(item), FakeRedis()))
        verdict = matched.action if matched else "SAFE"
        assert verdict == item["expected_verdict"], item["id"]
        if matched:
            matching_rule_ids.add(matched.id)

    assert matching_rule_ids == {rule.id for rule in rules}


def test_deny_wins_over_divert_and_path_rules_are_evaluated_first():
    rules = [
        Rule(
            id="learned-divert",
            owasp="A02",
            match_type="path",
            pattern="/admin",
            action="DIVERT",
            source="learned",
            description="Path divert",
        ),
        Rule(
            id="pack-deny",
            owasp="A05",
            match_type="regex",
            target="query",
            pattern="union",
            action="DENY",
            source="pack",
            description="Regex deny",
        ),
    ]
    engine = RuleEngine()
    engine.replace_rules(rules)

    result = asyncio.run(
        engine.evaluate(
            RequestContext(path="/admin", query="union", headers={}, body=""),
            FakeRedis(),
        )
    )

    assert result is not None
    assert result.id == "pack-deny"


def test_disabled_rules_are_not_evaluated():
    rule = Rule(
        id="disabled",
        owasp="A05",
        match_type="regex",
        target="query",
        pattern="malicious",
        action="DENY",
        source="pack",
        description="Disabled rule",
        enabled=False,
    )
    engine = RuleEngine()
    engine.replace_rules([rule])

    assert (
        asyncio.run(
            engine.evaluate(
                RequestContext(path="/", query="malicious", headers={}, body=""),
                FakeRedis(),
            )
        )
        is None
    )


def test_any_rule_update_reloads_the_full_active_list():
    first = Rule(
        id="first",
        owasp="A05",
        match_type="path",
        pattern="/first",
        action="DENY",
        source="pack",
        description="First active rule",
    )
    second = first.model_copy(update={"id": "second", "pattern": "/second"})
    third = first.model_copy(update={"id": "third", "pattern": "/third"})

    class FakeRedis:
        def __init__(self):
            self.values = {"first": first.model_dump_json()}
            self.read_count = 0

        async def hgetall(self, key):
            assert key == "rules:active"
            self.read_count += 1
            return self.values

    class FakePubSub:
        def __init__(self, redis):
            self.redis = redis
            self.subscribed = None

        async def subscribe(self, channel):
            self.subscribed = channel

        async def listen(self):
            self.redis.values = {"second": second.model_dump_json()}
            yield {"type": "message", "data": "second"}
            self.redis.values = {"third": third.model_dump_json()}
            yield {"type": "message", "data": "*"}

    async def run():
        redis = FakeRedis()
        pubsub = FakePubSub(redis)
        engine = RuleEngine()
        await reload_active_rules(redis, engine)
        await listen_for_rule_updates(redis, pubsub, engine)
        return redis, pubsub, engine

    redis, pubsub, engine = asyncio.run(run())

    assert pubsub.subscribed == "rules:updated"
    assert redis.read_count == 3
    assert [rule.id for rule in engine.rules] == ["third"]


class FakeRedis:
    def __init__(self):
        self.counters = {}

    async def eval(self, script, key_count, key, window):
        assert key_count == 1
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]


def test_p2_path_rate_rules_and_anomaly_score():
    rules = load_all_pack_rules()
    engine = RuleEngine()
    engine.replace_rules(rules)
    redis = FakeRedis()

    for path in ("/admin", "/debug"):
        denied = asyncio.run(
            engine.evaluate(
                RequestContext(path=path, query="", headers={}, body=""),
                redis,
            )
        )
        assert denied is not None
        assert denied.owasp == "A02"

    internal = asyncio.run(
        engine.evaluate(
            RequestContext(
                path="/api/statements/fetch",
                query="url=http%3A%2F%2Fbank%3A8001%2Fhealth",
                headers={},
                body="",
            ),
            redis,
        )
    )
    assert internal is not None
    assert internal.id == "access-003"

    login_context = RequestContext(
        path="/api/login",
        query="",
        headers={},
        body='{"email":"customer1@example.test"}',
        ip="192.0.2.10",
    )
    login_decisions = [
        asyncio.run(engine.evaluate(login_context, redis)) for _ in range(6)
    ]
    assert [decision is not None for decision in login_decisions] == [
        False,
        False,
        False,
        False,
        False,
        True,
    ]
    assert login_decisions[-1].id == "rate-001"

    transfer_context = RequestContext(
        path="/api/transfer",
        query="",
        headers={},
        body='{"from_account_id":31}',
        ip="192.0.2.10",
    )
    transfer_decisions = [
        asyncio.run(engine.evaluate(transfer_context, redis)) for _ in range(6)
    ]
    assert [decision is not None for decision in transfer_decisions] == [
        False,
        False,
        False,
        False,
        False,
        True,
    ]
    assert transfer_decisions[-1].id == "rate-002"
    assert transfer_decisions[-1].action == "DIVERT"


def test_p2_corpus_items_match_their_labels():
    engine = RuleEngine()
    engine.replace_rules(load_all_pack_rules())
    redises: dict = {}
    items = [item for item in load_corpus() if item["id"] > "c-0040"]

    for item in items:
        # rate counters per OWASP category, like tests/e2e (bursts are counted within their own category)
        redis = redises.setdefault(item["owasp"], FakeRedis())
        rule = asyncio.run(engine.evaluate(make_context(item), redis))
        if rule is not None:
            verdict = rule.action
        else:
            verdict = "DIVERT" if score_request(make_context(item))[0] >= 0.7 else "SAFE"
        assert verdict == item["expected_verdict"], item["id"]


def test_anomaly_score_is_bounded_and_benign_corpus_stays_below_threshold():
    benign = [
        item
        for item in load_corpus()
        if item["label"] == "benign"
    ]
    assert all(score_request(make_context(item))[0] < 0.7 for item in benign)

    unusual = RequestContext(
        path="/unexpected/route/" + "x" * 500,
        query="surprise=" + "%2F%3C%3E" * 30,
        headers={},
        body='{"unseen":"<script>"' + "!" * 300 + "}",
    )
    score, components = score_request(unusual)
    assert 0.7 <= score <= 1.0
    assert set(components) == {
        "length",
        "special_characters",
        "unseen_path",
        "unseen_params",
    }
