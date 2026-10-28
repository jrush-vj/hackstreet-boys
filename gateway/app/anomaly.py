import json
import re
from urllib.parse import parse_qsl

from .engine import RequestContext

ROUTE_BASELINES = {
    "/api/login": 110,
    "/api/accounts/{id}": 120,
    "/api/transfer": 150,
    "/api/transactions/search": 120,
    "/api/transactions/{id}/memo": 130,
    "/api/support/chat": 210,
    "/api/statements/fetch": 150,
    "/admin": 120,
    "/debug": 120,
}
KNOWN_QUERY_PARAMS = {"q", "url", "view"}
KNOWN_BODY_PARAMS = {
    "amount",
    "email",
    "from_account_id",
    "message",
    "memo",
    "password",
    "to_account_id",
}


def _normalized_path(path: str) -> str:
    path = re.sub(r"(?<=/accounts/)\d+(?=/|$)", "{id}", path)
    return re.sub(r"(?<=/transactions/)\d+(?=/|$)", "{id}", path)


def score_request(context: RequestContext) -> tuple[float, dict[str, float]]:
    normalized_path = _normalized_path(context.path)
    raw = f"{context.path}?{context.query}{context.body}"
    route_baseline = ROUTE_BASELINES.get(normalized_path)
    length_score = (
        min(max(0, len(raw) - route_baseline) / route_baseline, 1.0)
        if route_baseline
        else 1.0
    )
    special_ratio = (
        sum(not (char.isalnum() or char.isspace()) for char in raw) / len(raw)
        if raw
        else 0.0
    )
    special_score = min(special_ratio / 0.5, 1.0)
    path_score = 0.0 if route_baseline else 1.0

    param_names = {name for name, _ in parse_qsl(context.query, keep_blank_values=True)}
    try:
        body = json.loads(context.body) if context.body else {}
    except json.JSONDecodeError:
        body = {}
    if isinstance(body, dict):
        param_names.update(body)
    known_params = KNOWN_QUERY_PARAMS | KNOWN_BODY_PARAMS
    unknown_count = len(param_names - known_params)
    param_score = min(unknown_count / max(len(param_names), 1), 1.0)

    components = {
        "length": length_score * 0.3,
        "special_characters": special_score * 0.35,
        "unseen_path": path_score * 0.15,
        "unseen_params": param_score * 0.2,
    }
    return round(min(sum(components.values()), 1.0), 4), components
