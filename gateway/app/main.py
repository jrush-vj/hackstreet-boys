"""P0 stub (Jerush). Abhinav replaces this with the real proxy + rule engine in P1."""

import uuid

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from shared.config import settings  # noqa: F401  proves shared/ is wired in

app = FastAPI(title="gateway")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def stub_proxy(path: str):
    rid = str(uuid.uuid4())
    return JSONResponse(
        {"stub": "gateway", "verdict": "SAFE", "path": f"/{path}", "request_id": rid},
        headers={"X-Request-Id": rid, "X-Verdict": "SAFE"},
    )
