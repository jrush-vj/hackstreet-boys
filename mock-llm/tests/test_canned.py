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
