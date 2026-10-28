"""Contracts from docs/04-system-design.md sections 5, 6 and 9. The doc wins if they disagree."""

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

OwaspId = Literal["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
Verdict = Literal["SAFE", "DIVERT", "DENY"]
MatchType = Literal["regex", "rate", "path", "header"]
Target = Literal["path", "query", "body", "header", "any"]
Action = Literal["DENY", "DIVERT"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RequestInfo(BaseModel):
    method: str
    path: str
    query: str = ""
    ip: str
    user_agent: str = ""
    body_excerpt: str = ""  # max 500 chars, truncated
    body_sha256: str = ""


class Event(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    ts: datetime = Field(default_factory=utcnow)
    source: Literal["gateway", "sandbox", "honeypot", "analyst", "runner"]
    correlation_id: str  # gateway's X-Request-Id
    verdict: Verdict | None = None
    owasp: OwaspId | None = None
    rule_id: str | None = None
    score: float = 0.0
    request: RequestInfo
    scenario_step: str | None = None
    details: dict = {}


class Rule(BaseModel):
    id: str  # pack: "sqli-001"; learned: "L-" + 8 hex
    owasp: OwaspId
    match_type: MatchType
    target: Target = "any"
    pattern: str = ""
    params: dict = {}  # rate: {"key":"ip"|"account","limit":10,"window_s":60}
    action: Action
    source: Literal["pack", "learned"]
    description: str
    created_at: datetime = Field(default_factory=utcnow)
    enabled: bool = True
    hits: int = 0


class RuleProposal(BaseModel):
    """What the defense LLM must return (section 9). The analyst turns it into a Rule."""

    owasp: OwaspId
    match_type: MatchType
    target: Target = "any"
    pattern: str = ""
    params: dict = {}
    action: Action
    description: str
