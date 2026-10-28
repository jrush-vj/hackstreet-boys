"""P3 learning loop (docs/04-system-design.md section 9): a DIVERTed request becomes a validated DENY rule.

DIVERT event → wait up to 2 s for its honeypot/sandbox events → ask the defense LLM for one RuleProposal
→ validate (schema, regex compiles, 3–300 chars, matches the triggering request, ≤ 1% of the last 500 SAFE
requests) → retry once → canned fallback (shared/canned.py) → store as L-xxxxxxxx, push to Redis, publish.
The model only proposes; this module decides. DEMO_OFFLINE=1 or "AI off" in the console = canned only.
"""

import asyncio
import fnmatch
import json
import re
import secrets
import time
from urllib.parse import unquote_plus

import httpx

from app import store
from shared.canned import CANNED, PROMPT_CANNED
from shared.events import emit
from shared.owasp import OWASP_2025
from shared.schemas import Event, Rule, RuleProposal

FP_SAMPLE, FP_MAX_RATIO = 500, 0.01
RELATED_WAIT_S = 2.0

# Where an anomaly-only DIVERT (no OWASP id yet) most likely belongs, by route. The model can disagree.
ROUTE_HINTS = [
    (r"^/api/transfer", "A06"), (r"^/api/login", "A07"), (r"^/api/accounts/[^/]*[^/0-9]", "A10"),
    (r"^/api/accounts/", "A01"), (r"^/api/statements", "A01"), (r"^/(admin|debug)", "A02"),
    (r"^/api/(transactions|support)", "A05"),
]

SYSTEM = (
    "You are a defensive security analyst writing detection rules for a web application gateway. "
    "You are shown one request the gateway flagged as suspicious. Propose ONE rule that blocks requests "
    "like it without blocking normal traffic. Reply with a single JSON object only, keys: "
    '"owasp" (A01..A10), "match_type" ("regex"|"path"|"rate"|"header"), "target" ("path"|"query"|"body"|"header"|"any"), '
    '"pattern" (Python regex, 3-300 chars), "params" (object, {} unless rate), "action" ("DENY"), "description" (one sentence).'
)


def guess_owasp(path: str) -> str:
    return next((owasp for rx, owasp in ROUTE_HINTS if re.search(rx, path)), "A05")


def as_request(req: dict) -> dict:
    """The parts of an event's request that rules look at."""
    return {"path": req.get("path", ""), "query": req.get("query", ""),
            "body": req.get("body_excerpt", ""), "headers": {"user-agent": req.get("user_agent", "")}}


def _texts(target: str, r: dict) -> list[str]:
    """Same targets the gateway's RuleEngine uses (gateway/app/engine.py)."""
    headers = [f"{k}: {v}" for k, v in r["headers"].items()]
    return {
        "path": [r["path"]], "query": [r["query"], unquote_plus(r["query"])], "body": [r["body"]],
        "header": headers, "any": [r["path"], r["query"], unquote_plus(r["query"]), r["body"], *headers],
    }[target]


def matches(p, r: dict) -> bool:
    """Would rule/proposal `p` fire on request `r`? Rate rules count as matching their path (the counter
    decides later); used for the trigger check, the false-positive check and de-duplication."""
    if p.match_type in ("path", "rate"):
        return fnmatch.fnmatchcase(r["path"], p.pattern)
    rx = re.compile(p.pattern, re.IGNORECASE)
    if p.match_type == "header":
        return any(rx.search(h) for h in _texts("header", r))
    return any(rx.search(t) for t in _texts(p.target, r))


def validate(p: RuleProposal, trigger: dict, safe: list[dict]) -> str | None:
    """None if the proposal may go live, else the reason it may not."""
    if not 3 <= len(p.pattern) <= 300:
        return f"pattern length {len(p.pattern)} is outside 3–300"
    if p.match_type in ("regex", "header"):
        try:
            re.compile(p.pattern)
        except re.error as e:
            return f"regex does not compile: {e}"
    if p.match_type == "rate":
        prm = p.params
        if prm.get("key") not in ("ip", "account") or not all(
                isinstance(prm.get(k), int) and prm[k] >= 1 for k in ("limit", "window_s")):
            return "rate params need key ip|account and integer limit/window_s ≥ 1"
    if not matches(p, trigger):
        return "does not match the request it was learned from"
    if p.match_type != "rate":  # a rate rule on a normal route 'matches' every SAFE request by design
        hits = sum(matches(p, s) for s in safe)
        if hits > len(safe) * FP_MAX_RATIO:
            return f"would match {hits} of the last {len(safe)} SAFE requests (> 1%)"
    return None


def parse_proposal(content: str) -> RuleProposal:
    """First JSON object in the reply (after any reasoning block) → RuleProposal."""
    text = content.split("</think>")[-1]
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the reply")
    obj, _ = json.JSONDecoder().raw_decode(text[start:])
    return RuleProposal.model_validate(obj)


def build_prompt(ev: Event, related: list[dict], owasp: str) -> str:
    """Only the fields section 9 allows: method, path, query, body excerpt, verdict, score, sandbox/honeypot details."""
    r = ev.request
    extra = [{"source": e["source"], **{k: v for k, v in (e.get("details") or {}).items()
                                       if k in ("status", "error", "stack_trace_leaked", "served", "route")}}
             for e in related if e["source"] in ("sandbox", "honeypot")]
    return json.dumps({
        "method": r.method, "path": r.path, "query": r.query, "body_excerpt": r.body_excerpt[:500],
        "verdict": ev.verdict, "anomaly_score": ev.score, "related_events": extra,
        "likely_owasp": f"{owasp} ({OWASP_2025[owasp]})",
    })


def auth_header(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"} if key else {}  # mock mode has no key: send no header at all


async def ask_model(cfg: dict, prompt: str, status: dict) -> RuleProposal:
    base = cfg["base_url"].rstrip("/").removesuffix("/v1")
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=45) as c:
            r = await c.post(f"{base}/v1/chat/completions",
                             headers=auth_header(cfg["api_key"]),
                             json={"model": cfg["model"], "temperature": 0, "max_tokens": 400,
                                   "messages": [{"role": "system", "content": SYSTEM},
                                                {"role": "user", "content": prompt}]})
        r.raise_for_status()
        status.update(state="online", last_latency_ms=round((time.perf_counter() - t0) * 1000), last_error=None)
    except httpx.HTTPError as e:
        status.update(state="unreachable", last_error=str(e)[:200])
        raise
    return parse_proposal(r.json()["choices"][0]["message"]["content"])


async def _related(pool, correlation_id: str) -> list[dict]:
    """Honeypot/sandbox events for the same request; the sandbox replay may take a moment."""
    end = time.time() + RELATED_WAIT_S
    while True:
        rows = await pool.fetch("SELECT data FROM events WHERE correlation_id = $1", correlation_id)
        evs = [json.loads(x["data"]) for x in rows]
        if any(e["source"] == "sandbox" for e in evs) or time.time() >= end:
            return evs
        await asyncio.sleep(0.2)


async def _safe_requests(pool) -> list[dict]:
    rows = await pool.fetch("SELECT data FROM events WHERE source = 'gateway' AND verdict = 'SAFE' "
                            "ORDER BY ts DESC LIMIT $1", FP_SAMPLE)
    return [as_request(json.loads(x["data"])["request"]) for x in rows]


async def _note(state, ev: Event, action: str, kind_data: dict) -> None:
    """Analyst note: stored for the honeypot console, pushed live, and emitted as an analyst event."""
    await state.pool.execute("INSERT INTO analyses (kind, data) VALUES ('commentary', $1)", json.dumps(kind_data))
    await state.hp_hub.send({"type": "analysis", **kind_data})
    await emit(state.redis, Event(source="analyst", correlation_id=ev.correlation_id, owasp=None,
                                  request=ev.request, details={"action": action, "rule_id": kind_data.get("rule_id"),
                                                               "detail": kind_data["commentary"]}))


async def learn(state, ev: Event, from_stream: bool = True) -> tuple[Rule | None, str]:
    """One DIVERT → at most one new learned rule. Serialized, so a burst of DIVERTs learns once."""
    async with state.learn_lock:
        pool, redis = state.pool, state.redis
        if from_stream and not await pool.fetchval("SELECT 1 FROM events WHERE id = $1", ev.id):
            return None, "discarded: the demo was reset after this request"
        trigger = as_request(ev.request.model_dump())
        for r in await store.list_rules(pool):
            if r.source == "learned" and r.enabled and matches(r, trigger):
                return None, f"already covered by {r.id}"
        related = await _related(pool, ev.correlation_id)
        owasp = ev.owasp or guess_owasp(ev.request.path)
        safe = await _safe_requests(pool)
        cfg = await state.llm_cfg(redis)
        proposal, source, problems = None, "offline", []
        # a zero-day upload: the sandbox found an unknown dangerous entry; its name becomes the rule
        scan = (ev.details or {}).get("file_scan") or {}
        for name in scan.get("indicators", [])[:1]:
            candidate = RuleProposal(owasp="A08", match_type="regex", target="body", pattern=re.escape(name),
                                     params={}, action="DENY",
                                     description=f"Upload carries an unknown dangerous entry '{name[:60]}' (learned from a zero-day upload)")
            if validate(candidate, trigger, safe) is None:
                proposal, source = candidate, "scanner"
        if proposal is None and cfg["enabled"]:
            prompt = build_prompt(ev, related, owasp)
            for _ in range(2):  # the model gets one retry
                try:
                    p = await ask_model(cfg, prompt, state.llm_status)
                except Exception as e:  # unreachable, bad JSON, schema mismatch
                    problems.append(f"model: {str(e)[:120]}")
                    continue
                why = validate(p, trigger, safe)
                if why is None:
                    proposal, source = p, "llm"
                    break
                problems.append(f"rejected: {why}")
        if proposal is None:  # canned fallback, validated like anything else
            table = PROMPT_CANNED if "/support/" in ev.request.path else CANNED  # chat → prompt family, else SQL
            canned = RuleProposal(owasp=owasp, **table[owasp])
            why = validate(canned, trigger, safe)
            if why:
                reason = "; ".join(problems + [f"canned {owasp} rejected: {why}"])
                await _note(state, ev, "rule_rejected", {"source": source, "risk": 6, "intent": OWASP_2025[owasp],
                            "technique": "no rule", "commentary": f"No rule learned for {ev.request.path}: {reason}"})
                return None, reason
            proposal = canned

        rule = Rule(id=f"L-{secrets.token_hex(4)}", owasp=proposal.owasp, match_type=proposal.match_type,
                    target=proposal.target, pattern=proposal.pattern, params=proposal.params, action="DENY",
                    source="learned", description=proposal.description)
        await pool.execute("INSERT INTO learned_meta (rule_id, correlation_id, first_seen, owasp) VALUES ($1,$2,$3,$4)",
                           rule.id, ev.correlation_id, ev.ts, rule.owasp)
        rule = await store.upsert_rule(pool, rule)
        await store.publish_rule(redis, rule)
        await state.hub.on_rule(rule)
        # the anomaly-only DIVERT now has a category, so the OWASP scoreboard counts it
        await pool.execute(
            "UPDATE events SET owasp = $1, data = jsonb_set(data::jsonb, '{owasp}', to_jsonb($1::text))::jsonb "
            "WHERE correlation_id = $2 AND owasp IS NULL", rule.owasp, ev.correlation_id)
        await _note(state, ev, "rule_learned", {
            "source": source, "risk": 7, "rule_id": rule.id, "intent": OWASP_2025[rule.owasp],
            "technique": f"{rule.match_type} rule on {rule.target}",
            "commentary": f"{ev.request.method} {ev.request.path} looked like {rule.owasp} {OWASP_2025[rule.owasp]}. "
                          f"Learned {rule.id}: {rule.description}. The next similar request is denied.",
        })
        store.log("rule learned", rule_id=rule.id, owasp=rule.owasp, source=source, problems=problems)
        return rule, f"learned {rule.id} ({source})"
