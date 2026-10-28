"""OpenAI-compatible stand-in for the defense LLM. Returns a canned RuleProposal
picked by the first OWASP id (A01..A10) found in the prompt; A05 if none."""

import json
import re
import time
import uuid

from fastapi import FastAPI

from shared.canned import CANNED, PROMPT_CANNED
from shared.schemas import RuleProposal

app = FastAPI(title="mock-llm")

OWASP_RE = re.compile(r"\bA(0[1-9]|10)\b")


def proposal_for(prompt: str) -> dict:
    m = OWASP_RE.search(prompt)
    owasp = f"A{m.group(1)}" if m else "A05"
    table = PROMPT_CANNED if "/api/support/" in prompt else CANNED
    return RuleProposal(owasp=owasp, **table[owasp]).model_dump()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat/completions")
def chat_completions(body: dict):
    # the last user message describes the request; the system prompt lists every OWASP id, so ignore it
    users = [m for m in body.get("messages", []) if m.get("role") == "user"]
    prompt = str(users[-1].get("content", "")) if users else ""
    content = json.dumps(proposal_for(prompt))
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "mock"),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
    }
