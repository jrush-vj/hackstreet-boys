"""OpenAI-compatible stand-in for the defense LLM. Returns a canned RuleProposal
picked by the first OWASP id (A01..A10) found in the prompt; A05 if none."""

import json
import re
import time
import uuid

from fastapi import FastAPI

from shared.canned import CANNED
from shared.schemas import RuleProposal

app = FastAPI(title="mock-llm")

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
