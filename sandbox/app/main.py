"""P0 stub (Jerush). Abhinav implements the real replay in P2."""

from fastapi import FastAPI

from shared.config import settings  # noqa: F401  proves shared/ is wired in

app = FastAPI(title="sandbox")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/replay", status_code=202)
def replay(body: dict):
    # contract: {correlation_id, method, path, query, headers, body_b64}
    return {"accepted": True, "correlation_id": body.get("correlation_id")}
