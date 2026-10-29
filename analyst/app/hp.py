"""Honeypot console backend: the API that sentinel-trap's SOC dashboard (served at /honeypot/) expects,
built from our own events, rules and Redis ban list. Mounted at /api/hp/* and /ws/hp.

Our Event → sentinel event:  gateway SAFE → request · DIVERT → routed_to_honeypot · DENY → blocked
(canary-* → canary_hit, banned → blocked, L-* → learned_rule_caught) · honeypot/sandbox →
honeypot_interaction · analyst details.action (rule_learned, banned, marked_safe, …).
Attacker identity is the client IP the gateway saw (honeypot/sandbox events are joined by correlation_id).
"""

import json
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Header, HTTPException, Request, WebSocket, WebSocketDisconnect

from app import store
from app.learner import auth_header
from shared.config import settings
from shared.owasp import OWASP_2025

SAFE_COUNT_KEY = "hp:false_positives_fixed"
# Bans are DISPLAY-ONLY: the gateway never reads them, so nobody is actually blocked. Each one is a
# Redis key that expires on its own (and Reset demo deletes them), so the demo can always be rerun.
BAN_PREFIX, BAN_TTL_S = "hp:ban:", 600
LLM_CONFIG_KEY = "llm:config"
MAX_ACTIONS = 8
TRAPPED_FOR_S = 15 * 60  # a session with honeypot activity in the last 15 min is "trapped"

router = APIRouter()


async def _bans(redis) -> dict[str, dict]:
    out = {}
    async for key in redis.scan_iter(match=BAN_PREFIX + "*"):
        raw = await redis.get(key)
        if raw:
            out[key[len(BAN_PREFIX):]] = json.loads(raw)
    return out


async def _ban(redis, ip: str, reason: str) -> None:
    await redis.set(BAN_PREFIX + ip, json.dumps({"reason": reason, "ts": time.time()}), ex=BAN_TTL_S)


def require_admin(token: str | None) -> None:
    if token != settings.admin_token:
        raise HTTPException(401, "admin token rejected")


# ---------------------------------------------------------------- event mapping

def _category(ev: dict) -> str:
    cat = (ev.get("details") or {}).get("category")
    if cat:
        return cat
    path = ev["request"]["path"]
    if "/support/chat" in path:
        return "prompt_injection"
    if "/memo" in path:
        return "log_injection"
    if "/search" in path:
        return "sqli"
    return (OWASP_2025.get(ev.get("owasp") or "", "") or "").lower().replace(" ", "_")


def _payload(ev: dict) -> str:
    r = ev["request"]
    s = r["path"] + (f"?{r['query']}" if r.get("query") else "")
    if r.get("body_excerpt"):
        s += " " + r["body_excerpt"][:200]
    return s


def _action(ev: dict) -> str:
    src, verdict, rule = ev["source"], ev.get("verdict"), ev.get("rule_id") or ""
    if src == "gateway":
        if verdict == "SAFE":
            return "request"
        if verdict == "DIVERT":
            return "routed_to_honeypot"
        if rule.startswith("canary-"):
            return "canary_hit"
        if rule.startswith("L-"):
            return "learned_rule_caught"
        return "blocked"
    if src in ("honeypot", "sandbox"):
        return "honeypot_interaction"
    return (ev.get("details") or {}).get("action", "system")


def to_st(ev: dict, ip_by_corr: dict[str, str]) -> dict:
    d = ev.get("details") or {}
    ip = ip_by_corr.get(ev["correlation_id"], ev["request"]["ip"]) if ev["source"] != "gateway" else ev["request"]["ip"]
    action = _action(ev)
    path = ev["request"]["path"]
    if ev["source"] == "sandbox":
        detail = f"sandbox replay: HTTP {d.get('status')}" + (" · stack trace leaked" if d.get("stack_trace_leaked") else "")
    else:
        detail = d.get("served") or d.get("detail") or ""
    return {
        "id": ev["id"], "ts": ev["ts"], "action": action,
        "session_id": ip, "attacker_ip": ip, "fingerprint": (ev["request"].get("user_agent") or "-")[:32],
        "channel": "system" if ev["source"] in ("analyst", "sandbox") else
                   "prompt" if "/support/chat" in path else "log" if "/memo" in path else "web",
        "payload": _payload(ev) if ev["source"] != "analyst" else d.get("payload", ""),
        "risk": {"request": 0, "routed_to_honeypot": 7, "honeypot_interaction": 8}.get(action, 9),
        "rule_id": ev.get("rule_id") or d.get("rule_id"),
        "detail": detail,
        "extra": {"category": _category(ev), "kind": d.get("kind"), "sample": d.get("sample"),
                  "served": d.get("served"), "canary": d.get("canary", False)},
    }


async def _recent(pool, limit: int = 2000) -> list[dict]:
    rows = await pool.fetch("SELECT data FROM events ORDER BY ts DESC LIMIT $1", limit)
    return [json.loads(r["data"]) for r in rows]


def _ip_by_corr(evs: list[dict]) -> dict[str, str]:
    return {e["correlation_id"]: e["request"]["ip"] for e in evs if e["source"] == "gateway"}


# ---------------------------------------------------------------- live feed (/ws/hp)

class HpHub:
    """Pushes sentinel-shaped messages to the honeypot console."""

    def __init__(self, redis) -> None:
        self.redis = redis
        self.clients: set[WebSocket] = set()
        self.ip_by_corr: dict[str, str] = {}

    async def send(self, msg: dict) -> None:
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                self.clients.discard(ws)

    async def on_event(self, ev) -> None:
        data = ev.model_dump(mode="json")
        if data["source"] == "gateway":
            self.ip_by_corr[data["correlation_id"]] = data["request"]["ip"]
            if len(self.ip_by_corr) > 5000:  # bounded: keep the newest half
                self.ip_by_corr = dict(list(self.ip_by_corr.items())[2500:])
            if (data.get("rule_id") or "").startswith("canary-"):
                await _ban(self.redis, data["request"]["ip"], f"reused a honeypot canary key ({data['rule_id']})")
        if self.clients:
            await self.send({"type": "event", "event": to_st(data, self.ip_by_corr)})


@router.websocket("/ws/hp")
async def hp_ws(ws: WebSocket):
    await ws.accept()
    hub: HpHub = ws.app.state.hp_hub
    hub.clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)


# ---------------------------------------------------------------- read endpoints

@router.get("/api/hp/events")
async def hp_events(request: Request, limit: int = 100):
    evs = await _recent(request.app.state.pool, 2000)
    corr = _ip_by_corr(evs)
    return [to_st(e, corr) for e in evs[: max(1, min(limit, 500))]]


async def _sessions(request: Request) -> list[dict]:
    redis, pool = request.app.state.redis, request.app.state.pool
    evs = await _recent(pool)
    corr = _ip_by_corr(evs)
    banned = set(await _bans(redis))
    by_ip: dict[str, dict] = {}
    for e in reversed(evs):  # oldest first
        st = to_st(e, corr)
        ip = st["attacker_ip"]
        if st["action"] == "request":
            continue
        s = by_ip.setdefault(ip, {"session_id": ip, "attacker_ip": ip, "fingerprint": st["fingerprint"],
                                  "account": None, "timeline": [], "actions": 0, "canary": False,
                                  "rule_ids": [], "last": 0.0, "trapped": False})
        s["timeline"].append({"action": st["action"], "payload": st["payload"], "detail": st["detail"]})
        s["last"] = datetime.fromisoformat(e["ts"]).timestamp()
        if st["action"] == "routed_to_honeypot":
            s["trapped"] = True
        if st["action"] == "honeypot_interaction" and e["source"] == "honeypot":
            s["actions"] += 1
        if st["action"] == "canary_hit":
            s["canary"] = True
        if st["rule_id"] and st["rule_id"] not in s["rule_ids"]:
            s["rule_ids"].append(st["rule_id"])
    out = []
    now = time.time()
    for ip, s in by_ip.items():
        if not s["trapped"] and not s["canary"]:
            continue  # only people who reached the honeypot (or reused its canaries) have a session
        status = "banned" if ip in banned else "trapped" if now - s["last"] < TRAPPED_FOR_S else "ended"
        out.append({**s, "status": status, "max_actions": MAX_ACTIONS,
                    "risk": min(10, 5 + s["actions"] + (3 if s["canary"] else 0))})
    return sorted(out, key=lambda s: s["last"], reverse=True)


@router.get("/api/hp/sessions")
async def hp_sessions(request: Request):
    return await _sessions(request)


@router.get("/api/hp/stats")
async def hp_stats(request: Request):
    pool, redis = request.app.state.pool, request.app.state.redis
    rows = await pool.fetch(
        "SELECT verdict, rule_id, count(*) AS n FROM events WHERE source='gateway' GROUP BY verdict, rule_id")
    total = sum(r["n"] for r in rows)
    attacks = sum(r["n"] for r in rows if r["verdict"] in ("DIVERT", "DENY"))
    diverts = sum(r["n"] for r in rows if r["verdict"] == "DIVERT")
    catches = sum(r["n"] for r in rows if r["verdict"] == "DENY" and (r["rule_id"] or "").startswith("L-"))
    hp_n = await pool.fetchval("SELECT count(*) FROM events WHERE source='honeypot'")
    trapped = await pool.fetchval(
        "SELECT count(DISTINCT data->'request'->>'ip') FROM events WHERE source='gateway' AND verdict='DIVERT'")
    return {
        "requests": total, "attacks_detected": attacks, "attackers_trapped": trapped,
        "attackers_banned": len(await _bans(redis)),
        "rules_learned": await pool.fetchval("SELECT count(*) FROM rules WHERE source='learned'"),
        "false_positives_fixed": int(await redis.get(SAFE_COUNT_KEY) or 0),
        "learned_catches": catches,
        "by_action": {"request": total - attacks, "routed_to_honeypot": diverts, "honeypot_interaction": hp_n},
    }


GROUP_NAMES = {"sqli": "SQL injection", "prompt": "Prompt injection", "logi": "Log injection"}


def _st_rule(r) -> dict:
    return {"id": r.id, "source": r.source, "enabled": r.enabled, "hits": r.hits,
            "category": f"{GROUP_NAMES.get(r.id.split('-')[0], OWASP_2025[r.owasp])} · {r.owasp}",
            "regex": r.pattern if r.match_type in ("regex", "header", "path") else
                     f"rate {r.pattern} > {r.params.get('limit')}/{r.params.get('window_s')}s per {r.params.get('key')}"}


@router.get("/api/hp/rules")
async def hp_rules(request: Request):
    return [_st_rule(r) for r in await store.list_rules(request.app.state.pool)]


@router.get("/api/hp/bans")
async def hp_bans(request: Request):
    bans = await _bans(request.app.state.redis)
    return [{"ip": ip, "fingerprint": "", "account": None,
             "reason": f"{b['reason']} · temporary, display only"} for ip, b in sorted(bans.items())]


MASKED = {  # what the real tables hold, masked: the console shows these next to the decoys sent
    "transactions": [{"label": "transactions.description", "value": "████████ (2,000 rows)"},
                     {"label": "transactions.amount", "value": "██.██"}],
    "api_keys": [{"label": "api_keys", "value": "no such table in VulnBank"},
                 {"label": "staff.email", "value": "a****@example.test"}],
    "schema": [{"label": "sqlite_master", "value": "customers, accounts, transactions, staff, sessions"}],
    "secrets": [{"label": "DATABASE_URL", "value": "postgresql://████:████@postgres/sphere"}],
    "prompt": [{"label": "support bot prompt", "value": "████ (internal note never sent)"}],
    "logs": [{"label": "bank log", "value": "unchanged: forged lines never reached it"}],
}


@router.get("/api/hp/data-contrast")
async def hp_contrast(request: Request, limit: int = 8):
    evs = await _recent(request.app.state.pool, 2000)
    corr = _ip_by_corr(evs)
    out = []
    for e in evs:
        d = e.get("details") or {}
        if e["source"] != "honeypot" or not d.get("kind"):
            continue
        sample = d.get("sample")
        rows = sample if isinstance(sample, list) else [{"name": "reply", "value": str(sample or "")}]
        fake = [{"label": r.get("name", ""), "value": r.get("value", ""),
                 "canary": "CANARY" in str(r.get("value", ""))} for r in rows]
        out.append({"id": e["id"], "ts": e["ts"], "kind": d["kind"], "attacker_ip": corr.get(e["correlation_id"], "?"),
                    "payload": _payload(e), "real": MASKED.get(d["kind"], []), "fake": fake,
                    "canaries": sum(f["canary"] for f in fake)})
        if len(out) >= limit:
            break
    return out


@router.get("/api/hp/sandbox")
async def hp_sandbox(request: Request, limit: int = 30):
    """Uploads scanned by the sandbox and requests replayed in it, newest first."""
    evs = await _recent(request.app.state.pool, 2000)
    corr = _ip_by_corr(evs)
    rows = []
    for e in evs:
        d = e.get("details") or {}
        if e["source"] == "gateway" and d.get("file_scan"):
            fs = d["file_scan"]
            rows.append({"kind": "upload", "verdict": e.get("verdict") or fs["verdict"], "ts": e["ts"],
                         "path": e["request"]["path"], "attacker_ip": e["request"]["ip"], "score": fs["score"],
                         "components": fs.get("components", {}), "indicators": fs.get("indicators", []),
                         "rule_id": e.get("rule_id") or fs.get("rule_id")})
        elif e["source"] == "sandbox":
            rows.append({"kind": "replay", "verdict": "REPLAYED", "ts": e["ts"], "path": e["request"]["path"],
                         "attacker_ip": corr.get(e["correlation_id"], "?"), "score": 0.0,
                         "components": {"http_status": d.get("status"), "latency_ms": d.get("latency_ms")},
                         "indicators": [], "rule_id": None})
    return rows[: max(1, min(limit, 200))]


@router.get("/api/hp/analyses")
async def hp_analyses(request: Request, limit: int = 40):
    rows = await request.app.state.pool.fetch(
        "SELECT kind, data FROM analyses ORDER BY id DESC LIMIT $1", max(1, min(limit, 200)))
    return [{"kind": r["kind"], **json.loads(r["data"])} for r in rows]


# ---------------------------------------------------------------- AI analyst status / settings

async def _llm_cfg(redis) -> dict:
    over = await redis.hgetall(LLM_CONFIG_KEY)
    env_url = settings.local_llm_url if settings.llm_mode == "local" else settings.defense_llm_url
    return {"base_url": over.get("base_url") or env_url, "api_key": over.get("api_key") or settings.defense_llm_key,
            "model": over.get("model") or "qwen",
            "enabled": over.get("enabled", "1") == "1" and not settings.demo_offline}


@router.get("/api/hp/llm/status")
async def hp_llm_status(request: Request):
    cfg = await _llm_cfg(request.app.state.redis)
    st = request.app.state.llm_status
    return {"state": "disabled" if not cfg["enabled"] else st["state"], "enabled": cfg["enabled"],
            "mode": settings.llm_mode, "last_latency_ms": st["last_latency_ms"], "last_error": st["last_error"],
            "circuit_open_for_s": 0}


@router.get("/api/hp/llm/config")
async def hp_llm_config(request: Request, x_admin_token: str | None = Header(None)):
    require_admin(x_admin_token)  # the model URL is internal: only the admin may read it
    cfg = await _llm_cfg(request.app.state.redis)
    key = cfg["api_key"]
    return {**cfg, "api_key": (key[:4] + "…" + key[-2:]) if len(key) > 8 else ("set" if key else "")}


@router.post("/api/hp/llm/config")
async def hp_llm_config_save(request: Request, x_admin_token: str | None = Header(None)):
    require_admin(x_admin_token)
    body = await request.json()
    cfg = {"enabled": "1" if body.get("enabled") else "0"}
    for k in ("base_url", "api_key", "model"):
        if str(body.get(k) or "").strip():  # empty = keep the current value
            cfg[k] = str(body[k]).strip()
    await request.app.state.redis.hset(LLM_CONFIG_KEY, mapping=cfg)
    await request.app.state.hp_hub.send({"type": "llm"})
    return {"ok": True}


@router.post("/api/hp/llm/test")
async def hp_llm_test(request: Request, x_admin_token: str | None = Header(None)):
    require_admin(x_admin_token)
    cfg = await _llm_cfg(request.app.state.redis)
    base = cfg["base_url"].rstrip("/").removesuffix("/v1")
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"{base}/v1/models", headers=auth_header(cfg["api_key"]))
        return {"ok": r.status_code == 200, "status": r.status_code, "latency_ms": round((time.perf_counter() - t0) * 1000),
                "base_url": base}
    except httpx.HTTPError as e:
        return {"ok": False, "error": str(e), "base_url": base}


# ---------------------------------------------------------------- actions

async def _console_ban(request: Request, ip: str, reason: str) -> None:
    await _ban(request.app.state.redis, ip, reason)
    await request.app.state.hp_hub.send({"type": "event", "event": {
        "id": f"ban-{ip}-{time.time()}", "ts": datetime.now(timezone.utc).isoformat(), "action": "banned",
        "session_id": ip, "attacker_ip": ip, "fingerprint": "-", "channel": "system", "payload": "",
        "risk": 10, "rule_id": None, "detail": reason, "extra": {}}})


@router.post("/api/hp/mark-safe")
async def hp_mark_safe(request: Request, x_admin_token: str | None = Header(None)):
    require_admin(x_admin_token)
    body = await request.json()
    redis = request.app.state.redis
    ip = body.get("ip") or body.get("account") or ""
    if ip:
        await redis.delete(BAN_PREFIX + ip)
    if body.get("rule_id"):
        rule = await store.set_enabled(request.app.state.pool, body["rule_id"], False)
        if rule:
            await store.publish_rule(redis, rule)
            await request.app.state.hub.on_rule(rule)
    await redis.incr(SAFE_COUNT_KEY)
    return {"ok": True}


@router.post("/api/hp/rules/{rule_id}/toggle")
async def hp_toggle(rule_id: str, request: Request, x_admin_token: str | None = Header(None)):
    require_admin(x_admin_token)
    pool = request.app.state.pool
    current = next((r for r in await store.list_rules(pool) if r.id == rule_id), None)
    if current is None:
        raise HTTPException(404, f"no rule {rule_id}")
    rule = await store.set_enabled(pool, rule_id, not current.enabled)
    await store.publish_rule(request.app.state.redis, rule)
    await request.app.state.hub.on_rule(rule)
    return _st_rule(rule)


async def _final_report(request: Request, ended_now: list[str]) -> dict:
    sessions = await _sessions(request)
    rules = await store.list_rules(request.app.state.pool)
    learned = [r for r in rules if r.source == "learned"]
    stats = await hp_stats(request)
    blocked = await request.app.state.pool.fetchval(  # repeat attacks stopped by canary or learned rules
        "SELECT count(*) FROM events WHERE source='gateway' AND verdict='DENY' AND (rule_id LIKE 'canary-%' OR rule_id LIKE 'L-%')")
    attackers = []
    for s in sessions:
        attacks = [t for t in s["timeline"] if t["action"] in ("routed_to_honeypot", "blocked", "canary_hit",
                                                                 "learned_rule_caught")]
        caught = [t for t in attacks if t["action"] != "routed_to_honeypot"]
        attackers.append({
            "attacker_ip": s["attacker_ip"], "fingerprint": s["fingerprint"], "account": None,
            "status": s["status"], "canary": s["canary"], "actions": s["actions"], "risk": s["risk"],
            "banned": s["status"] == "banned", "activity": s["timeline"][-12:],
            "return_check": {"payloads_checked": len(attacks), "caught": len(caught),
                             "learned_rule_ids": [r for r in s["rule_ids"] if r.startswith("L-")]},
            "analysis": None,
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(), "ended_now": ended_now, "unfinished": [],
        "totals": {**{k: stats[k] for k in ("requests", "attacks_detected", "attackers_trapped",
                                             "attackers_banned", "rules_learned", "learned_catches")},
                   "blocked": blocked},
        "attackers": attackers,
        "learned_rules": [_st_rule(r) for r in learned],
    }


@router.post("/api/hp/ban-account")
async def hp_ban_account(request: Request, x_admin_token: str | None = Header(None)):
    require_admin(x_admin_token)
    ip = (await request.json()).get("account", "")
    if ip:
        await _console_ban(request, ip, "banned from the honeypot console")
    return await _final_report(request, [ip] if ip else [])


@router.post("/api/hp/ban-all")
async def hp_ban_all(request: Request, x_admin_token: str | None = Header(None)):
    require_admin(x_admin_token)
    trapped = [s["attacker_ip"] for s in await _sessions(request) if s["status"] == "trapped"]
    for ip in trapped:
        await _console_ban(request, ip, "banned with all trapped attackers")
    report = await _final_report(request, trapped)
    await request.app.state.hp_hub.send({"type": "final_report"})
    return report


@router.get("/api/hp/final-report")
async def hp_report(request: Request):
    return await _final_report(request, [])


@router.post("/api/hp/reset")
async def hp_reset(request: Request, x_admin_token: str | None = Header(None)):
    """Clear events, bans, rate counters and learned rules; pack rules are reloaded. LLM settings are kept."""
    require_admin(x_admin_token)
    async with request.app.state.learn_lock:  # never reset in the middle of learning a rule
        await store.reset_demo(request.app.state.pool, request.app.state.redis, request.app.state.packs_dir)
    await request.app.state.hp_hub.send({"type": "reset"})
    return {"ok": True}
