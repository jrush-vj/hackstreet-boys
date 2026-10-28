"""Send a folder of samples through the gateway and report what the system did with each one.

    python tests/e2e/run_samples.py <folder> [--base http://localhost:8000] [--twice]

Samples are only read as bytes and uploaded. Nothing is executed or extracted on this machine.
Only the gateway may be targeted (AGENTS.md section 7): localhost:8000 or gateway:8000.
--twice sends every file a second time, to show whether the system learned from the first pass.
"""

import argparse
import sys
from pathlib import Path

import httpx

ALLOWED_BASES = {"http://localhost:8000", "http://gateway:8000"}
MAX_BYTES = 5 * 1024 * 1024  # the sandbox scanner's own limit


def send(client: httpx.Client, base: str, path: Path) -> tuple:
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        return "skipped", f"{len(data)} bytes > {MAX_BYTES} limit", None
    ctype = "application/zip" if data[:4] == b"PK\x03\x04" else "application/octet-stream"
    r = client.post(f"{base}/api/statements/upload", content=data, headers={"content-type": ctype})
    rule = r.json().get("rule_id") if r.headers.get("content-type", "").startswith("application/json") else None
    return r.headers.get("x-verdict", "?"), f"HTTP {r.status_code}", rule


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", type=Path)
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--twice", action="store_true")
    args = ap.parse_args()
    if args.base not in ALLOWED_BASES:
        print(f"refused: {args.base} is not an allowed gateway (AGENTS.md section 7)", file=sys.stderr)
        return 2
    files = sorted(p for p in args.folder.rglob("*") if p.is_file())
    if not files:
        print("no files in", args.folder, file=sys.stderr)
        return 1
    passes = 2 if args.twice else 1
    with httpx.Client(timeout=60) as client:
        for n in range(1, passes + 1):
            print(f"--- pass {n}")
            print(f"{'sample':40} {'verdict':8} {'status':12} rule")
            for p in files:
                verdict, status, rule = send(client, args.base, p)
                print(f"{p.name[:40]:40} {verdict:8} {status:12} {rule or ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
