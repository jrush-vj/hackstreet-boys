import json
import fnmatch
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus

from redis.asyncio import Redis

from shared.schemas import Rule

RATE_COUNTER = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


@dataclass(frozen=True)
class RequestContext:
    path: str
    query: str
    headers: Mapping[str, str]
    body: str
    ip: str = "unknown"


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
            if rule.match_type == "rate":
                try:
                    key_type = rule.params["key"]
                    limit = int(rule.params["limit"])
                    window = int(rule.params["window_s"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Invalid rate parameters in rule {rule.id}"
                    ) from exc
                if key_type not in {"ip", "account"} or limit < 1 or window < 1:
                    raise ValueError(f"Invalid rate parameters in rule {rule.id}")
        self._rules = enabled_rules
        self._patterns = patterns

    async def evaluate(self, context: RequestContext, redis: Redis) -> Rule | None:
        groups = (
            [rule for rule in self._rules if rule.match_type == "path"],
            [rule for rule in self._rules if rule.match_type == "rate"],
            [
                rule
                for rule in self._rules
                if rule.match_type in {"regex", "header"}
            ],
        )
        first_divert = None
        for group in groups:
            rules = sorted(
                group,
                key=lambda rule: (rule.source != "pack", rule.id),
            )
            for rule in rules:
                if rule.match_type == "rate":
                    matched = await self._matches_rate(rule, context, redis)
                else:
                    matched = self._matches(rule, context)
                if not matched:
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

    async def _matches_rate(
        self, rule: Rule, context: RequestContext, redis: Redis
    ) -> bool:
        if not fnmatch.fnmatchcase(context.path, rule.pattern):
            return False
        params = rule.params
        window = int(params["window_s"])
        limit = int(params["limit"])
        key_type = params["key"]
        identity = context.ip
        if key_type == "account":
            try:
                body = json.loads(context.body)
            except json.JSONDecodeError:
                body = {}
            if not isinstance(body, dict):
                body = {}
            identity = str(
                body.get("from_account_id", body.get("account_id", context.ip))
            )
        key = f"rate:{rule.id}:{identity}"
        count = await redis.eval(RATE_COUNTER, 1, key, window)
        return int(count) > limit


async def load_active_rules(redis: Redis) -> list[Rule]:
    values = await redis.hgetall("rules:active")
    rules = [Rule.model_validate_json(value) for value in values.values()]
    return [rule for rule in rules if rule.enabled]
