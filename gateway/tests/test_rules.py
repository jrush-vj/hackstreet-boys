import asyncio
import json
from pathlib import Path

import yaml

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


def load_pack_rules() -> list[Rule]:
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

    assert len(corpus) == 40
    assert sum(item["label"] == "benign" for item in corpus) == 20
    assert sum(item["label"] == "malicious" for item in corpus) == 20

    for item in corpus:
        matched = engine.evaluate(make_context(item))
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

    result = engine.evaluate(
        RequestContext(path="/admin", query="union", headers={}, body="")
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

    assert engine.evaluate(
        RequestContext(path="/", query="malicious", headers={}, body="")
    ) is None


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
