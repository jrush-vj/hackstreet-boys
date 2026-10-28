import re

from app.main import CANNED, proposal_for
from shared.owasp import OWASP_2025


def test_every_owasp_id_has_a_valid_proposal():
    assert set(CANNED) == set(OWASP_2025)
    for owasp in OWASP_2025:
        p = proposal_for(f"verdict DIVERT, owasp {owasp}")
        assert p["owasp"] == owasp
        assert 3 <= len(p["pattern"]) <= 300  # analyst validator bounds (design doc section 9)
        if p["match_type"] == "regex":
            re.compile(p["pattern"])


def test_defaults_to_a05():
    assert proposal_for("no id here")["owasp"] == "A05"


def test_reads_the_user_message_not_the_system_prompt():
    from fastapi.testclient import TestClient

    from app.main import app

    body = {"messages": [{"role": "system", "content": "owasp A01..A10"},
                         {"role": "user", "content": '{"likely_owasp": "A06 (Insecure Design)"}'}]}
    content = TestClient(app).post("/v1/chat/completions", json=body).json()["choices"][0]["message"]["content"]
    assert '"owasp": "A06"' in content
