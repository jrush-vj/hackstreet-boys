# 01 — Overview

## The problem

Signature-based defenses only block attacks they already know. A zero-day, an attack
pattern nobody has written a rule for yet, gets through. Our system catches
the *unknown* request, studies it safely, learns a rule and blocks the next
one like it.

## The idea in one line

> Gateway decides SAFE / DIVERT / DENY. DIVERTed traffic goes to a sandbox and a honeypot,
> an AI analyst turns what it saw into a new rule, and the gateway DENYs the
> next similar request in milliseconds.

## The three verdicts

| Verdict | When | What happens | Dashboard |
|---|---|---|---|
| SAFE | No rule matches, anomaly score below threshold | Forwarded to `bank` | Green row |
| DIVERT | No rule matches, but anomaly score ≥ threshold (possible zero-day) | Attacker is answered by `honeypot`; a copy is replayed in `sandbox`; `analyst` may learn a rule | Amber row + "learning" badge |
| DENY | A predefined or learned rule matches | 403, logged | Red row + rule id + OWASP tag |

## Two kinds of rules

1. **Predefined rule packs**, loaded at start: SQL injection, prompt injection,
   log injection (all OWASP A05). They prove the DENY path from minute one.
2. **Learned rules**, written by the defense LLM after a DIVERT. They prove the
   zero-day story.

## OWASP Top 10:2025 coverage

Source: [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/).
Changes from 2021: SSRF folded into A01; A03 and A10 are new.

| ID | Category | Where VulnBank shows it | Expected verdict | Demo |
|---|---|---|---|---|
| A01 | Broken Access Control (incl. SSRF) | Viewing another customer's account; "fetch statement from URL" | DENY | Live |
| A02 | Security Misconfiguration | Admin and debug routes left open | DENY | Live |
| A03 | Software Supply Chain Failures | Outdated pinned dependency found by a scan | n/a | Slide + clip |
| A04 | Cryptographic Failures | Login accepted over plain HTTP, weak hashing | DIVERT | Slide + clip |
| A05 | Injection | Search (SQL), support chat (prompt), memo field (log) | DENY (rule packs) | Live |
| A06 | Insecure Design | Transfer endpoint with no business limits | DIVERT → learned DENY | Live (the zero-day moment) |
| A07 | Authentication Failures | Login with no lockout | DENY after threshold | Live |
| A08 | Software or Data Integrity Failures | Session token not signature-checked | DIVERT | Slide + clip |
| A09 | Security Logging & Alerting Failures | VulnBank logs nothing; our gateway + dashboard is the fix | Shown by dashboard | Live |
| A10 | Mishandling of Exceptional Conditions | Error pages leak stack traces; fail-open on bad input | DIVERT | Live |

7 categories are demoed live and 3 shown on a slide with a recorded clip.

## Why this wins

- Built on an industry framework (OWASP 2025, the current list).
- Shows learning, not just blocking: the "first seen → blocked" timer.
- Honest scope. Judges see exactly what's live and what's roadmap.
