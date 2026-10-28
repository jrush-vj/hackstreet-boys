"""OpenAI-compatible stand-in for the defense LLM. Returns a canned RuleProposal
picked by the first OWASP id (A01..A10) found in the prompt; A05 if none."""

import json
import re
import time
import uuid

from fastapi import FastAPI

from shared.schemas import RuleProposal

app = FastAPI(title="mock-llm")

CANNED: dict[str, dict] = {
    "A01": {"match_type": "regex", "target": "query", "action": "DENY",
            "pattern": r"(?i)url=https?://(127\.|10\.|169\.254\.|localhost|bank)",
            "description": "Statement fetch pointed at an internal host"},
    "A02": {"match_type": "regex", "target": "path", "action": "DENY",
            "pattern": r"^/(admin|debug)(/|$)",
            "description": "Admin or debug route reached from outside"},
    "A03": {"match_type": "regex", "target": "header", "action": "DIVERT",
            "pattern": r"(?i)x-dependency-scan:\s*vulnerable",
            "description": "Placeholder: supply chain is shown on a slide"},
    "A04": {"match_type": "regex", "target": "header", "action": "DIVERT",
            "pattern": r"(?i)x-forwarded-proto:\s*http$",
            "description": "Login over plain HTTP"},
    "A05": {"match_type": "regex", "target": "any", "action": "DENY",
            "pattern": r"(?i)(\bunion\b.+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1)",
            "description": "SQL injection tautology or UNION SELECT"},
    "A06": {"match_type": "rate", "target": "path", "action": "DENY",
            "pattern": "/api/transfer", "params": {"key": "account", "limit": 3, "window_s": 60},
            "description": "Transfer burst from one account"},
    "A07": {"match_type": "rate", "target": "path", "action": "DENY",
            "pattern": "/api/login", "params": {"key": "ip", "limit": 5, "window_s": 60},
            "description": "Login burst from one IP"},
    "A08": {"match_type": "regex", "target": "header", "action": "DENY",
            "pattern": r"(?i)authorization:\s*bearer\s+[\w-]+\.[\w-]+\.\s*$",
            "description": "Unsigned session token (empty signature)"},
    "A09": {"match_type": "regex", "target": "any", "action": "DIVERT",
            "pattern": r"(?i)(%0a|%0d|\\n)",
            "description": "Placeholder: log-forging characters"},
    "A10": {"match_type": "regex", "target": "body", "action": "DIVERT",
            "pattern": r"(%00|\\x00|\{\{|\]\]\])",
            "description": "Malformed input that triggers unhandled errors"},
}
OWASP_RE = re.compile(r"\bA(0[1-9]|10)\b")


def proposal_for(prompt: str) -> dict:
    m = OWASP_RE.search(prompt)
    owasp = f"A{m.group(1)}" if m else "A05"
    return RuleProposal(owasp=owasp, **CANNED[owasp]).model_dump()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat/completions")
def chat_completions(body: dict):
    prompt = "\n".join(str(m.get("content", "")) for m in body.get("messages", []))
    content = json.dumps(proposal_for(prompt))
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "mock"),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
    }
