"""P0 stub. The real runner (scenario replay with target allowlist) comes in P4."""

import uuid

from fastapi import FastAPI

from shared.config import settings  # noqa: F401  proves shared/ is wired in

app = FastAPI(title="runner")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/run")
def run(body: dict):
    return {"run_id": f"stub-{uuid.uuid4().hex[:8]}"}


@app.get("/runs/{run_id}")
def run_status(run_id: str):
    return {"run_id": run_id, "scenario": None, "status": "done", "steps": []}
