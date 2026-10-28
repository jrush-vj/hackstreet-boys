"""Benchmark cached in-process verdict evaluation with the loaded gateway rule packs."""

import asyncio
import math
import time
from pathlib import Path

import yaml
from app.anomaly import score_request
from app.engine import RequestContext, RuleEngine

from shared.schemas import Rule

ITERATIONS = 1000
WARMUP_ITERATIONS = 100
P95_LIMIT_MS = 5.0


class NoopRedis:
    async def eval(self, script: str, key_count: int, key: str, window: int) -> int:
        raise AssertionError("benchmark request unexpectedly matched a rate rule")


def load_pack_rules() -> list[Rule]:
    rules = []
    pack_dir = Path(__file__).parent / "rules" / "packs"
    for path in sorted(pack_dir.glob("*.yaml")):
        for item in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            rules.append(Rule.model_validate({**item, "source": "pack"}))
    return rules


async def benchmark() -> float:
    engine = RuleEngine()
    engine.replace_rules(load_pack_rules())
    redis = NoopRedis()
    context = RequestContext(
        path="/api/accounts/1",
        query="",
        headers={"accept": "application/json"},
        body="",
    )

    async def verdict() -> None:
        rule = await engine.evaluate(context, redis)
        if rule is None:
            score_request(context)

    for _ in range(WARMUP_ITERATIONS):
        await verdict()

    samples = []
    for _ in range(ITERATIONS):
        started = time.perf_counter_ns()
        await verdict()
        samples.append(time.perf_counter_ns() - started)

    p95_ns = sorted(samples)[math.ceil(0.95 * len(samples)) - 1]
    p95_ms = p95_ns / 1_000_000
    print(f"cached-rule verdict p95: {p95_ms:.3f} ms ({ITERATIONS} iterations)")
    if p95_ms >= P95_LIMIT_MS:
        raise SystemExit(f"p95 verdict time must be under {P95_LIMIT_MS} ms")
    return p95_ms


if __name__ == "__main__":
    asyncio.run(benchmark())
