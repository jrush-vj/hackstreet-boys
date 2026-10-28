-- P3 learning loop. learned_meta: when the pattern behind a learned rule was first seen (for /api/timers).
-- analyses: analyst notes shown in the honeypot console. IF NOT EXISTS: safe on every start.
CREATE TABLE IF NOT EXISTS learned_meta (rule_id text PRIMARY KEY, correlation_id text,
  first_seen timestamptz, owasp text);
CREATE TABLE IF NOT EXISTS analyses (id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(),
  kind text, data jsonb);
