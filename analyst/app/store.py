"""Postgres + Redis access for the analyst. The analyst is the only writer of both."""

import json
from pathlib import Path

import asyncpg
import yaml

from shared.schemas import Event, Rule

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"
RULES_HASH = "rules:active"
RULES_CHANNEL = "rules:updated"


def log(msg: str, **kw) -> None:
    print(json.dumps({"svc": "analyst", "msg": msg, **kw}, default=str), flush=True)


async def migrate(pool: asyncpg.Pool) -> None:
    # shortcut: re-runs every file each start (all idempotent); add a version table if a migration ever isn't
    for f in sorted(MIGRATIONS.glob("*.sql")):
        await pool.execute(f.read_text())


# ---------- events ----------

async def save_event(pool: asyncpg.Pool, ev: Event) -> None:
    await pool.execute(
        """INSERT INTO events (id, ts, source, verdict, owasp, rule_id, score, correlation_id, data)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING""",
        ev.id, ev.ts, ev.source, ev.verdict, ev.owasp, ev.rule_id, ev.score,
        ev.correlation_id, ev.model_dump_json(),
    )
    if ev.source == "gateway" and ev.verdict == "DENY" and ev.rule_id:
        await pool.execute("UPDATE rules SET hits = hits + 1 WHERE id = $1", ev.rule_id)


async def list_events(pool: asyncpg.Pool, since, limit: int) -> list[dict]:
    rows = await pool.fetch(
        "SELECT data FROM events WHERE ($1::timestamptz IS NULL OR ts > $1) ORDER BY ts DESC LIMIT $2",
        since, limit,
    )
    return [json.loads(r["data"]) for r in rows]


async def stats(pool: asyncpg.Pool, owasp_ids) -> dict:
    # Verdicts come only from the gateway; honeypot/sandbox events for the same request don't count twice.
    rows = await pool.fetch(
        "SELECT verdict, owasp, count(*) AS n FROM events "
        "WHERE source = 'gateway' AND verdict IS NOT NULL GROUP BY verdict, owasp"
    )
    totals = {"SAFE": 0, "DIVERT": 0, "DENY": 0}
    owasp = {k: {"DIVERT": 0, "DENY": 0} for k in owasp_ids}
    for r in rows:
        totals[r["verdict"]] += r["n"]
        if r["owasp"] in owasp and r["verdict"] in ("DIVERT", "DENY"):
            owasp[r["owasp"]][r["verdict"]] += r["n"]
    learned = await pool.fetchval("SELECT count(*) FROM rules WHERE source = 'learned'")
    return {"totals": totals, "owasp": owasp, "learned_rules": learned}


# ---------- rules ----------

def _rule_from_row(r) -> Rule:
    # enabled, hits and created_at live in their own columns; they win over the copy in `data`
    return Rule.model_validate({**json.loads(r["data"]), "enabled": r["enabled"], "hits": r["hits"],
                                "created_at": r["created_at"]})


async def list_rules(pool: asyncpg.Pool) -> list[Rule]:
    rows = await pool.fetch("SELECT data, enabled, hits, created_at FROM rules ORDER BY created_at, id")
    return [_rule_from_row(r) for r in rows]


async def upsert_rule(pool: asyncpg.Pool, rule: Rule) -> Rule:
    """Insert, or refresh the definition while keeping enabled/hits that were changed at runtime."""
    row = await pool.fetchrow(
        """INSERT INTO rules (id, owasp, source, enabled, hits, created_at, data)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (id) DO UPDATE SET owasp = EXCLUDED.owasp, source = EXCLUDED.source,
             data = EXCLUDED.data
           RETURNING data, enabled, hits, created_at""",
        rule.id, rule.owasp, rule.source, rule.enabled, rule.hits, rule.created_at,
        rule.model_dump_json(),
    )
    return _rule_from_row(row)


async def set_enabled(pool: asyncpg.Pool, rule_id: str, enabled: bool) -> Rule | None:
    row = await pool.fetchrow(
        "UPDATE rules SET enabled = $2 WHERE id = $1 RETURNING data, enabled, hits, created_at", rule_id, enabled
    )
    return _rule_from_row(row) if row else None


async def publish_rule(redis, rule: Rule) -> None:
    """rules:active holds enabled rules only; the gateway reloads on rules:updated."""
    if rule.enabled:
        await redis.hset(RULES_HASH, rule.id, rule.model_dump_json())
    else:
        await redis.hdel(RULES_HASH, rule.id)
    await redis.publish(RULES_CHANNEL, rule.id)


def read_packs(packs_dir: Path) -> list[Rule]:
    rules = []
    for f in sorted(packs_dir.glob("*.yaml")):
        for item in yaml.safe_load(f.read_text()) or []:
            rules.append(Rule.model_validate({**item, "source": "pack"}))
    return rules


async def load_packs(pool: asyncpg.Pool, redis, packs_dir: Path) -> int:
    """Packs → Postgres, then rebuild rules:active from every enabled rule (packs + learned)."""
    rules = read_packs(packs_dir) if packs_dir.is_dir() else []
    for rule in rules:
        await upsert_rule(pool, rule)
    active = {r.id: r.model_dump_json() for r in await list_rules(pool) if r.enabled}
    async with redis.pipeline(transaction=True) as p:
        p.delete(RULES_HASH)
        if active:
            p.hset(RULES_HASH, mapping=active)
        p.publish(RULES_CHANNEL, "*")
        await p.execute()
    log("rules loaded", packs=len(rules), active=len(active))
    return len(rules)
