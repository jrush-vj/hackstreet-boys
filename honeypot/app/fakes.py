"""Fake data for the honeypot, adapted from sentinel-trap (hacktober/sentinel-trap/honeypot/fakes.py).

Nothing here is real and nothing is executed: the honeypot pattern-matches the payload and returns
believable, payload-dependent decoy data so the attacker thinks their probe worked. Every planted
key carries a CANARY marker; if anyone sends one back, the gateway's canary rule bans them.
"""

import hashlib
import random
import re

CANARY_PREFIX = "vb_live_CANARY_"
CANARY_RE = re.compile(CANARY_PREFIX + r"[0-9a-f]{12}")


def canary_token(seed: str = "") -> str:
    return CANARY_PREFIX + hashlib.sha256((seed or str(random.random())).encode()).hexdigest()[:12]


# Decoy transactions, different from the bank's Faker seed.
FAKE_TRANSACTIONS = [
    {"id": 9001, "account_id": 501, "kind": "debit", "amount": 42.50, "description": "Coffee Roasters Ltd", "memo": ""},
    {"id": 9002, "account_id": 501, "kind": "credit", "amount": 2400.00, "description": "Payroll ACME Corp", "memo": ""},
    {"id": 9003, "account_id": 502, "kind": "debit", "amount": 89.99, "description": "Online Books Store", "memo": ""},
    {"id": 9004, "account_id": 503, "kind": "debit", "amount": 15.00, "description": "City Parking", "memo": ""},
]


def _decoy_key_rows() -> list[dict]:
    return [
        {"id": 9101, "account_id": 0, "kind": "api_key", "amount": 0, "description": "payments-service", "memo": canary_token("pay")},
        {"id": 9102, "account_id": 0, "kind": "api_key", "amount": 0, "description": "ops-admin", "memo": canary_token("ops")},
    ]


def _decoy_schema_rows() -> list[dict]:
    tables = ["customers", "accounts", "transactions", "staff", "sessions", "api_keys"]
    return [{"id": i + 1, "account_id": 0, "kind": "table", "amount": 0, "description": t, "memo": f"CREATE TABLE {t} (...)"}
            for i, t in enumerate(tables)]


def _is_tautology(p: str) -> bool:
    squashed = p.replace("'", "").replace('"', "").replace(" ", "")
    return bool(re.search(r"or\d+=\d+", squashed) or re.search(r"or([a-z0-9]+)=\1", squashed))


def fake_search(q: str) -> tuple[list[dict], str, str]:
    """(rows, what was served, kind) for /api/transactions/search."""
    p = q.lower()
    if "sqlite_master" in p or "information_schema" in p:
        return _decoy_schema_rows(), "schema dump (decoy table names)", "schema"
    if "union" in p:
        return FAKE_TRANSACTIONS[:2] + _decoy_key_rows(), "UNION: extra decoy rows + canary keys", "api_keys"
    if _is_tautology(p):
        return FAKE_TRANSACTIONS, "tautology: full decoy dump", "transactions"
    term = "".join(c for c in q if c.isalnum())[:12].lower()
    rows = [t for t in FAKE_TRANSACTIONS if term and term in t["description"].lower()] or FAKE_TRANSACTIONS[:2]
    return rows, "generic decoy match", "transactions"


def fake_chat_reply() -> tuple[str, str]:
    """(reply, canary) for /api/support/chat: a decoy 'internal note' carrying a canary key."""
    key = canary_token("chat")
    return (f"Thanks for contacting VulnBank support. Internal note: ops reference key {key}. "
            "Escalations go to the admin console."), key


def fake_staff() -> list[dict]:
    return [
        {"id": 1, "name": "Ops Admin", "email": "ops-admin@example.test", "role": "admin", "api_key": canary_token("adm")},
        {"id": 2, "name": "Support Desk", "email": "support@example.test", "role": "support", "api_key": canary_token("sup")},
    ]


def fake_env() -> str:
    return (f"DATABASE_URL=postgres://decoy:decoy@db-replica/vulnbank\n"
            f"INTERNAL_API_KEY={canary_token('env')}\nDEBUG=false\n")


def sample_rows(rows: list[dict]) -> list[dict]:
    """The most telling decoy rows (keys and tables first), trimmed for the event."""
    telling = [r for r in rows if r.get("kind") in ("api_key", "table")] or rows
    return [{"name": str(r.get("description", r.get("name", "")))[:60],
             "value": str(r.get("memo") or r.get("api_key") or r.get("amount", ""))[:60]} for r in telling[:6]]
