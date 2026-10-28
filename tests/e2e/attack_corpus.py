"""Replay the labelled MALICIOUS corpus items against the public gateway and report what the system did.

    python tests/e2e/attack_corpus.py --base https://attack.example.com --allow-host attack.example.com

Only corpus items with label "malicious" are sent (AGENTS.md section 7: no new attack tooling). The target host must
be named twice: it must match --allow-host, and only the gateway is allowed (never the bank, honeypot or analyst).
Local runs use --base http://localhost:8000 --allow-host localhost.
For the Access-protected public URL, set CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET (a Cloudflare service token).
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import httpx

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "corpus.jsonl"


def items() -> list[dict]:
    return [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()
            if line.strip() and json.loads(line)["label"] == "malicious"]


def send(client: httpx.Client, base: str, item: dict) -> tuple[str, str]:
    r = client.request(item["method"], base + item["path"], params=item.get("query") or None,
                       headers=item.get("headers") or {}, json=item.get("body"))
    rule = r.json().get("rule_id") if "json" in r.headers.get("content-type", "") else None
    return r.headers.get("x-verdict", "?"), rule or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--allow-host", required=True)
    args = ap.parse_args()
    parsed = urlparse(args.base)
    if parsed.hostname != args.allow_host:
        print(f"refused: --base host {parsed.hostname} is not --allow-host {args.allow_host}", file=sys.stderr)
        return 2
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
        print("refused: public targets must use https", file=sys.stderr)
        return 2
    summary: Counter = Counter()
    # Cloudflare Access service token (created in Zero Trust); without it the public URL answers with the login page
    headers = {}
    if os.getenv("CF_ACCESS_CLIENT_ID"):
        headers = {"CF-Access-Client-Id": os.environ["CF_ACCESS_CLIENT_ID"],
                   "CF-Access-Client-Secret": os.environ.get("CF_ACCESS_CLIENT_SECRET", "")}
    with httpx.Client(timeout=30, headers=headers) as client:
        print(f"{'id':8} {'owasp':6} {'expected':9} {'got':9} rule")
        for item in items():
            got, rule = send(client, args.base, item)
            ok = "" if got == item["expected_verdict"] else "  <-- differs"
            print(f"{item['id']:8} {str(item.get('owasp')):6} {item['expected_verdict']:9} {got:9} {rule}{ok}")
            summary[(item.get("owasp"), got)] += 1
    print("\nsummary (OWASP, verdict): count")
    for key in sorted(summary, key=str):
        print(f"  {key}: {summary[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
