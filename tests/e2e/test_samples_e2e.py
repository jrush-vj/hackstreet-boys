"""Dataset runner (run_samples.py) against structural stand-ins for the three public datasets. No real malware:
an APK-shaped zip with a classes.dex entry (CICMalDroid-style), a raw PE header (EMBER-style) and a benign archive.
The system must DIVERT the unknown ones, learn a rule from the APK entry name, and then DENY the same APK."""

import io
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import httpx

from test_g1 import ANALYST, GATEWAY

RUNNER = Path(__file__).with_name("run_samples.py")


def apk_like(tmp: Path) -> Path:
    p = tmp / "stand_in_app.apk"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("classes.dex", os.urandom(512))  # never executed: random bytes
    p.write_bytes(buf.getvalue())
    return p


def pe_like(tmp: Path) -> Path:
    p = tmp / "stand_in.exe"
    p.write_bytes(b"MZ" + os.urandom(2000))
    return p


def benign(tmp: Path) -> Path:
    p = tmp / "statement.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("march.csv", b"date,amount\n2026-03-01,12.50\n" * 20)
    p.write_bytes(buf.getvalue())
    return p


def test_runner_refuses_anything_but_the_gateway(tmp_path):
    out = subprocess.run([sys.executable, str(RUNNER), str(tmp_path), "--base", "http://example.com"],
                         capture_output=True, text=True)
    assert out.returncode == 2 and "refused" in out.stderr


def test_dataset_stand_ins_are_diverted_learned_and_benign_passes(tmp_path):
    benign_path, apk, pe = benign(tmp_path), apk_like(tmp_path), pe_like(tmp_path)
    for p in (benign_path, apk, pe):
        p.write_bytes(p.read_bytes())
    out = subprocess.run([sys.executable, str(RUNNER), str(tmp_path), "--base", GATEWAY],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    rows = {line.split()[0]: line.split()[1] for line in out.stdout.splitlines()[2:] if line.strip()}
    assert rows["statement.zip"] == "SAFE"
    assert rows["stand_in_app.apk"] == "DIVERT"
    assert rows["stand_in.exe"] == "DIVERT"
    # the APK's classes.dex becomes a learned rule; the next APK is denied by it
    end = httpx.get(f"{ANALYST}/api/rules").json()
    import time
    t = time.time()
    while time.time() - t < 15 and not any(r["source"] == "learned" and "classes" in r["pattern"] for r in
                                           httpx.get(f"{ANALYST}/api/rules").json()):
        time.sleep(0.3)
    assert any(r["source"] == "learned" and "classes" in r["pattern"] for r in httpx.get(f"{ANALYST}/api/rules").json())
    again = httpx.post(f"{GATEWAY}/api/statements/upload", content=apk.read_bytes(),
                       headers={"content-type": "application/zip"})
    assert again.status_code == 403 and again.json()["rule_id"].startswith("L-")
