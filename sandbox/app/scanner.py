"""Static file scanner for uploads. Runs in a child process (see main.py /scan) with memory and CPU limits.

The scanner knows no malware signatures: an upload is unknown until the system has learned it. It only scores
structure and content (the same idea as gateway/app/anomaly.py: named categories with weights).

Nothing in an upload is executed, and no payload is written to disk: archives are read from memory with zipfile.

Verdicts:
  DIVERT  score >= DIVERT_THRESHOLD -> honeypot + sandbox study it; the learner may add a DENY rule
  SAFE    otherwise                 -> forwarded to the bank
A learned rule (from `indicators`, the dangerous entry names) is what later blocks the same upload.
"""

import hashlib
import io
import json
import math
import os
import sys
import zipfile

DIVERT_THRESHOLD = float(os.getenv("DIVERT_THRESHOLD", "0.7"))

MAX_ENTRIES = 200
MAX_UNCOMPRESSED = 50 * 1024 * 1024
MAX_RATIO = 100
ENTROPY_SAMPLE = 64 * 1024
ENTROPY_LIMIT = 7.4
MAX_INDICATOR = 200

# category weights (sum capped at 1.0, like the request anomaly score)
WEIGHTS = {
    "archive_structure": {"traversal": 0.75, "too_many_entries": 0.3, "bomb": 0.75},
    "dangerous_content": {"executable": 0.75, "script": 0.75, "macro_office": 0.25, "nested_archive": 0.2},
    "encryption": {"password_protected": 0.4},
    "packing": {"high_entropy": 0.15},
}
EXEC_EXT = {".exe", ".dll", ".scr", ".msi", ".com", ".jar", ".elf", ".bin", ".apk", ".dex"}  # apk/dex: Android code
SCRIPT_EXT = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta", ".sh", ".py", ".wsf"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm"}
NESTED_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _ext(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return os.path.splitext(base)[1].lower()


def scan_bytes(data: bytes) -> dict:
    findings: list[str] = []
    indicators: list[str] = []  # names of dangerous entries, as they appear in the archive headers
    components: dict[str, float] = {}

    def hit(category: str, kind: str, why: str, indicator: str | None = None) -> None:
        w = WEIGHTS[category][kind]
        components[category] = min(1.0, components.get(category, 0.0) + w)
        findings.append(why)
        if indicator and indicator not in indicators:
            indicators.append(indicator[:MAX_INDICATOR])

    is_zip = data[:4] == b"PK\x03\x04"
    entries = 0
    if is_zip:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            hit("archive_structure", "bomb", "corrupt or unreadable archive")
            zf = None
        if zf is not None:
            infos = zf.infolist()
            entries = len(infos)
            total = sum(i.file_size for i in infos)
            packed = sum(i.compress_size for i in infos) or 1
            if entries > MAX_ENTRIES:
                hit("archive_structure", "too_many_entries", f"{entries} entries")
            if total > MAX_UNCOMPRESSED or total / packed > MAX_RATIO:
                hit("archive_structure", "bomb", f"expands to {total} bytes from {packed} (zip bomb pattern)")
            for info in infos:
                name = info.filename
                parts = name.replace("\\", "/").split("/")
                if name.startswith(("/", "\\")) or ".." in parts or ":" in name:
                    hit("archive_structure", "traversal", f"path traversal entry: {name[:80]}", name)
                ext = _ext(name)
                if ext in EXEC_EXT:
                    hit("dangerous_content", "executable", f"executable inside archive: {name[:80]}", name)
                elif ext in SCRIPT_EXT:
                    hit("dangerous_content", "script", f"script inside archive: {name[:80]}", name)
                elif ext in MACRO_EXT:
                    hit("dangerous_content", "macro_office", f"macro-enabled document: {name[:80]}")
                elif ext in NESTED_EXT:
                    hit("dangerous_content", "nested_archive", f"nested archive: {name[:80]}")
                if info.flag_bits & 0x1:
                    hit("encryption", "password_protected", f"password-protected entry: {name[:80]}")
            if total <= MAX_UNCOMPRESSED:  # only read payloads inside the size budget
                for info in infos:
                    if info.is_dir():
                        continue
                    try:
                        payload = zf.read(info)
                    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, ValueError):
                        continue  # encrypted or unsupported method: already flagged above if encrypted
                    if len(payload) > 4096 and _entropy(payload[:ENTROPY_SAMPLE]) > ENTROPY_LIMIT:
                        hit("packing", "high_entropy", f"high-entropy payload (packed or encrypted): {info.filename[:80]}")
    elif data[:2] == b"MZ" or data[:4] == b"\x7fELF":  # raw Windows PE or Linux ELF: no filename to learn from
        hit("dangerous_content", "executable", "raw executable body (PE/ELF)")
    elif len(data) > 4096 and _entropy(data[:ENTROPY_SAMPLE]) > ENTROPY_LIMIT:
        hit("packing", "high_entropy", "high-entropy body (packed or encrypted)")

    score = round(min(sum(components.values()), 1.0), 4)
    if score >= DIVERT_THRESHOLD:
        verdict, rule_id = "DIVERT", "file-anomaly"
    else:
        verdict, rule_id = "SAFE", None

    return {
        "verdict": verdict, "rule_id": rule_id, "score": score,
        "components": {k: round(v, 4) for k, v in components.items()},
        "findings": findings[:20], "indicators": indicators[:10], "entries": entries, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


if __name__ == "__main__":  # child process: raw bytes on stdin, JSON on stdout
    sys.stdout.write(json.dumps(scan_bytes(sys.stdin.buffer.read())))
