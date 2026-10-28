import fnmatch
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import unquote_plus

from redis.asyncio import Redis

from shared.schemas import Rule


@dataclass(frozen=True)
class RequestContext:
    path: str
    query: str
    headers: Mapping[str, str]
    body: str


class RuleEngine:
    def __init__(self) -> None:
        self._rules: tuple[Rule, ...] = ()
        self._patterns: dict[str, re.Pattern[str]] = {}

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def replace_rules(self, rules: Sequence[Rule]) -> None:
        enabled_rules = tuple(rule for rule in rules if rule.enabled)
        patterns: dict[str, re.Pattern[str]] = {}
        for rule in enabled_rules:
            if rule.match_type in {"regex", "header"}:
                try:
                    patterns[rule.id] = re.compile(rule.pattern, re.IGNORECASE)
                except re.error as exc:
                    raise ValueError(f"Invalid regex in rule {rule.id}: {exc}") from exc
        self._rules = enabled_rules
        self._patterns = patterns

    def evaluate(self, context: RequestContext) -> Rule | None:
        rules = sorted(
            self._rules,
            key=lambda rule: (rule.match_type != "path", rule.source != "pack", rule.id),
        )
        first_divert = None
        for rule in rules:
            if not self._matches(rule, context):
                continue
            if rule.action == "DENY":
                return rule
            if first_divert is None:
                first_divert = rule
        return first_divert

    def _matches(self, rule: Rule, context: RequestContext) -> bool:
        if rule.match_type == "path":
            return fnmatch.fnmatchcase(context.path, rule.pattern)

        pattern = self._patterns[rule.id]
        if rule.match_type == "header":
            return any(
                pattern.search(f"{name}: {value}")
                for name, value in context.headers.items()
            )

        targets = {
            "path": (context.path,),
            "query": (context.query, unquote_plus(context.query)),
            "body": (context.body,),
            "header": tuple(
                f"{name}: {value}" for name, value in context.headers.items()
            ),
            "any": (
                context.path,
                context.query,
                unquote_plus(context.query),
                context.body,
                *(f"{name}: {value}" for name, value in context.headers.items()),
            ),
        }
        return any(pattern.search(value) for value in targets[rule.target])


async def load_active_rules(redis: Redis) -> list[Rule]:
    values = await redis.hgetall("rules:active")
    rules = [Rule.model_validate_json(value) for value in values.values()]
    return [rule for rule in rules if rule.enabled]
