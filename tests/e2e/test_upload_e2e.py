"""Zero-day upload demo through the gateway. EICAR is NOT a known signature here: the first upload is an unknown
archive with an executable inside, so it is diverted to the honeypot and sandbox. The analyst learns a rule from
the entry name, and the same upload is then denied by that learned rule."""

import io
import time
import zipfile

import httpx

from test_g1 import ANALYST, GATEWAY

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
UPLOAD = f"{GATEWAY}/api/statements/upload"


def zipped(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def upload(body: bytes):
    return httpx.post(UPLOAD, content=body, headers={"content-type": "application/zip"}, timeout=30)


def learned_rules_for(name: str, timeout: float = 15) -> list[dict]:
    end = time.time() + timeout
    while time.time() < end:
        rules = [r for r in httpx.get(f"{ANALYST}/api/rules").json()
                 if r["source"] == "learned" and name.replace(".", "\.") in r["pattern"]]
        if rules:
            return rules
        time.sleep(0.3)
    return []


def test_zero_day_eicar_zip_is_diverted_learned_then_denied():
    body = zipped({"eicar.com": EICAR})
    first = upload(body)
    assert first.headers["X-Verdict"] == "DIVERT", "unknown archive with an executable must be studied, not denied"
    rules = learned_rules_for("eicar.com")
    assert rules, "the analyst did not learn a rule from the zero-day upload"
    again = upload(body)
    assert again.status_code == 403
    assert again.json()["rule_id"] == rules[0]["id"] and again.json()["owasp"] == "A08"


def test_zero_day_upload_reaches_honeypot_and_sandbox():
    r = upload(zipped({"sample.ps1": b"Write-Host zero-day"}))
    assert r.headers["X-Verdict"] == "DIVERT"
    rid = r.headers["X-Request-Id"]
    end = time.time() + 10
    seen = set()
    while time.time() < end and not {"gateway", "honeypot", "sandbox"} <= seen:
        evs = [e for e in httpx.get(f"{ANALYST}/api/events", params={"limit": 300}).json()
               if e["correlation_id"] == rid]
        seen = {e["source"] for e in evs}
        time.sleep(0.3)
    assert {"gateway", "honeypot", "sandbox"} <= seen
    gw = next(e for e in evs if e["source"] == "gateway")
    assert gw["details"]["file_scan"]["components"]["dangerous_content"] == 0.75
    assert gw["details"]["file_scan"]["indicators"] == ["sample.ps1"]


def test_clean_archive_is_forwarded_to_the_bank():
    r = upload(zipped({"march.txt": b"Opening balance 100.00\n" * 5}))
    assert r.headers["X-Verdict"] == "SAFE"  # the bank has no upload route yet: 404 is the bank answering


def test_sandbox_panel_lists_the_scanned_upload():
    upload(zipped({"panel.ps1": b"Write-Host panel"}))
    end = time.time() + 10
    rows = []
    while time.time() < end and not rows:
        rows = [r for r in httpx.get("http://localhost:3000/api/hp/sandbox", params={"limit": 30}).json()
                if r["kind"] == "upload" and "panel.ps1" in r["indicators"]]
        time.sleep(0.3)
    assert rows and rows[0]["verdict"] == "DIVERT" and rows[0]["components"]["dangerous_content"] == 0.75
