"""Static upload scanner (zero-day model: no malware signatures): docker compose run --rm sandbox pytest -q
Archives are built in memory; nothing is extracted or executed."""

import io
import os
import subprocess
import zipfile

from app.main import run_scanner
from app.scanner import scan_bytes

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def zipped(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_unknown_eicar_zip_diverts_as_zero_day_and_names_the_indicator():
    # no signature: the .com entry is an executable, so the archive is studied, not denied
    r = scan_bytes(zipped({"eicar.com": EICAR}))
    assert r["verdict"] == "DIVERT" and r["rule_id"] == "file-anomaly"
    assert r["components"]["dangerous_content"] == 0.75
    assert r["indicators"] == ["eicar.com"]


def test_eicar_text_without_an_archive_is_not_a_known_threat():
    # the scanner has no signature list; a plain 68-byte text file is simply SAFE
    r = scan_bytes(EICAR)
    assert r["verdict"] == "SAFE" and r["score"] == 0.0 and "signature" not in r["components"]


def test_clean_zip_is_safe_with_no_score():
    r = scan_bytes(zipped({"statement-march.txt": b"Opening balance 100.00\n" * 10}))
    assert r["verdict"] == "SAFE" and r["score"] == 0.0 and r["entries"] == 1 and r["indicators"] == []


def test_executable_inside_zip_diverts():
    r = scan_bytes(zipped({"invoice.pdf.exe": b"MZ" + os.urandom(200)}))
    assert r["verdict"] == "DIVERT" and r["components"]["dangerous_content"] == 0.75


def test_script_inside_zip_diverts():
    r = scan_bytes(zipped({"update.ps1": b"Write-Host hi"}))
    assert r["verdict"] == "DIVERT" and r["components"]["dangerous_content"] == 0.75


def test_zip_slip_path_diverts():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../etc/cron.d/x", b"* * * * * root id")
    r = scan_bytes(buf.getvalue())
    assert r["verdict"] == "DIVERT" and r["components"]["archive_structure"] == 0.75


def test_zip_bomb_pattern_diverts_without_expanding_it():
    r = scan_bytes(zipped({"big.bin": b"\0" * (60 * 1024 * 1024)}))
    assert r["verdict"] == "DIVERT" and r["components"]["archive_structure"] == 0.75


def test_corrupt_zip_is_not_passed_as_clean():
    r = scan_bytes(b"PK\x03\x04" + os.urandom(100))
    assert r["verdict"] == "DIVERT" and "corrupt" in r["findings"][0]


def test_macro_document_alone_is_recorded_but_not_diverted():
    r = scan_bytes(zipped({"report.docm": b"x"}))
    assert r["verdict"] == "SAFE" and r["components"]["dangerous_content"] == 0.25


def test_random_body_is_flagged_as_packed_but_stays_below_threshold():
    r = scan_bytes(os.urandom(64 * 1024))
    assert r["components"].get("packing") == 0.15 and r["verdict"] == "SAFE"


def test_child_process_scanner_matches_in_process_result():
    assert run_scanner(zipped({"eicar.com": EICAR}))["verdict"] == "DIVERT"
    assert run_scanner(zipped({"ok.txt": b"hello"}))["verdict"] == "SAFE"


def test_child_failure_is_fail_closed(monkeypatch):
    import app.main as sandbox_main

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="scanner", timeout=10)

    monkeypatch.setattr(sandbox_main.subprocess, "run", boom)
    r = sandbox_main.run_scanner(zipped({"ok.txt": b"hello"}))
    assert r["verdict"] == "DIVERT" and r["rule_id"] == "scan-error" and r["score"] == 1.0
