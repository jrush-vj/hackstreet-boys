"""P0 stub (Jerush). Akchhat mirrors the bank routes and emits events in P1/P2."""

from fastapi import FastAPI

from shared.config import settings  # noqa: F401  proves shared/ is wired in

app = FastAPI(title="honeypot")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def catch_all(path: str):
    return {"ok": True}
