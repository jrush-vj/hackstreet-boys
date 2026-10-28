-- docs/04-system-design.md section 11. IF NOT EXISTS so it is safe to run on every start.
CREATE TABLE IF NOT EXISTS events (id uuid PRIMARY KEY, ts timestamptz, source text, verdict text,
  owasp text, rule_id text, score real, correlation_id text, data jsonb);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);
CREATE INDEX IF NOT EXISTS events_correlation_idx ON events (correlation_id);
CREATE TABLE IF NOT EXISTS rules (id text PRIMARY KEY, owasp text, source text, enabled bool,
  hits int DEFAULT 0, created_at timestamptz, data jsonb);
