// Mirrors docs/04-system-design.md sections 5, 6 and 8 (analyst). The doc wins if they disagree.

export type OwaspId = "A01" | "A02" | "A03" | "A04" | "A05" | "A06" | "A07" | "A08" | "A09" | "A10";
export type Verdict = "SAFE" | "DIVERT" | "DENY";
export type Source = "gateway" | "sandbox" | "honeypot" | "analyst" | "runner";

export interface RequestInfo {
  method: string;
  path: string;
  query: string;
  ip: string;
  user_agent: string;
  body_excerpt: string;
  body_sha256: string;
}

export interface Event {
  id: string;
  ts: string;
  source: Source;
  correlation_id: string;
  verdict: Verdict | null;
  owasp: OwaspId | null;
  rule_id: string | null;
  score: number;
  request: RequestInfo;
  scenario_step: string | null;
  details: Record<string, unknown>;
}

export interface Rule {
  id: string;
  owasp: OwaspId;
  match_type: "regex" | "rate" | "path" | "header";
  target: "path" | "query" | "body" | "header" | "any";
  pattern: string;
  params: Record<string, unknown>;
  action: "DENY" | "DIVERT";
  source: "pack" | "learned";
  description: string;
  created_at: string;
  enabled: boolean;
  hits: number;
}

export interface Stats {
  totals: Record<Verdict, number>;
  owasp: Record<OwaspId, { DIVERT: number; DENY: number }>;
  learned_rules: number;
}

export interface Timer {
  rule_id: string;
  owasp: OwaspId;
  first_seen: string;
  rule_created: string;
  first_blocked: string;
  seconds: number;
}

export type LiveMessage =
  | { type: "event"; data: Event }
  | { type: "rule"; data: Rule }
  | { type: "stats"; data: Stats };

export const OWASP_2025: Record<OwaspId, string> = {
  A01: "Broken Access Control",
  A02: "Security Misconfiguration",
  A03: "Software Supply Chain Failures",
  A04: "Cryptographic Failures",
  A05: "Injection",
  A06: "Insecure Design",
  A07: "Authentication Failures",
  A08: "Software or Data Integrity Failures",
  A09: "Security Logging & Alerting Failures",
  A10: "Mishandling of Exceptional Conditions",
};

/** Shown on a slide with a recorded clip instead of live (docs/01-overview.md). */
export const ON_SLIDE: OwaspId[] = ["A03", "A04", "A08"];
