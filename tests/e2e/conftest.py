import httpx
import pytest


@pytest.fixture(autouse=True)
def reset_demo():
    # every test starts clean: no events, learned rules, display bans or rate counters (Reset demo button)
    r = httpx.post("http://localhost:8004/api/hp/reset", headers={"X-Admin-Token": "dev-admin-token"}, timeout=30)
    assert r.status_code == 200, r.text
