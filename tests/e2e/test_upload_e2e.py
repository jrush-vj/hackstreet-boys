"""File uploads through the gateway: the EICAR test zip is denied as known malware, a clean archive is forwarded,
a script or executable inside an archive is diverted to the honeypot, and the scan details reach the analyst."""

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


def test_eicar_zip_is_denied_as_malware():
    r = upload(zipped({"eicar.com": EICAR}))
    assert r.status_code == 403
    assert r.json()["rule_id"] == "malware-eicar" and r.json()["owasp"] == "A08"


def test_clean_archive_is_forwarded_to_the_bank():
    r = upload(zipped({"march.txt": b"Opening balance 100.00\n" * 5}))
    assert r.headers["X-Verdict"] == "SAFE"  # the bank has no upload route yet: 404 is the bank answering


def test_script_inside_zip_diverts_and_reaches_the_honeypot():
    r = upload(zipped({"update.ps1": b"Write-Host hi"}))
    assert r.headers["X-Verdict"] == "DIVERT"
    rid = r.headers["X-Request-Id"]
    end = time.time() + 10
    seen = set()
    while time.time() < end and not {"gateway", "honeypot"} <= seen:
        evs = [e for e in httpx.get(f"{ANALYST}/api/events", params={"limit": 300}).json()
               if e["correlation_id"] == rid]
        seen = {e["source"] for e in evs}
        time.sleep(0.3)
    assert {"gateway", "honeypot"} <= seen
    gw = next(e for e in evs if e["source"] == "gateway")
    assert gw["details"]["file_scan"]["components"]["dangerous_content"] == 0.75
    assert gw["details"]["file_scan"]["findings"]


def test_eicar_signature_inside_a_plain_body_is_denied():
    r = httpx.post(UPLOAD, content=EICAR, headers={"content-type": "text/plain"}, timeout=30)
    assert r.status_code == 403 and r.json()["rule_id"] == "malware-eicar"
