import { useEffect, useState } from "react";
import { ATTACKS } from "./attacks";
import {
  OWASP_2025,
  ON_SLIDE,
  type Event,
  type LiveMessage,
  type OwaspId,
  type Rule,
  type Stats,
  type Timer,
  type Verdict,
} from "./types";

const FEED_MAX = 100;
// Where the simulator buttons send attacks. Set only on the laptop (VITE_ATTACK_BASE); the homelab build leaves it
// unset, so visitors to graph.jrushvj.dev cannot fire attacks from the public dashboard.
const ATTACK_BASE: string | undefined = import.meta.env.VITE_ATTACK_BASE || undefined;

function fireAttacks(kind: keyof typeof ATTACKS) {
  if (!ATTACK_BASE) return;
  // one request every 400 ms, so each shows up as its own row on the public dashboard
  ATTACKS[kind].forEach((a, i) =>
    setTimeout(() => {
      fetch(ATTACK_BASE + a.path, {
        method: a.method,
        mode: "no-cors", // send only: the verdict is read on graph.jrushvj.dev, not here
        headers: a.body ? { "Content-Type": "application/x-www-form-urlencoded" } : {},
        body: a.body,
      }).catch(() => {});
    }, i * 400),
  );
}

const SCENARIO_STEPS = [
  { key: "normal", label: "Normal traffic" },
  { key: "rule", label: "Rule packs" },
  { key: "access", label: "Access + config" },
  { key: "login", label: "Login burst" },
  { key: "zero-day", label: "Zero-day moment" },
  { key: "error", label: "Error handling" },
  { key: "wrap-up", label: "Wrap-up" },
] as const;
const VERDICT_STYLE: Record<Verdict, string> = {
  SAFE: "border-emerald-500 bg-emerald-500/10",
  DIVERT: "border-amber-400 bg-amber-400/10",
  DENY: "border-red-500 bg-red-500/10",
};
const VERDICT_TEXT: Record<Verdict, string> = {
  SAFE: "text-emerald-400",
  DIVERT: "text-amber-300",
  DENY: "text-red-400",
};

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return r.json() as Promise<T>;
}

export default function App() {
  const [events, setEvents] = useState<Event[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [timers, setTimers] = useState<Timer[]>([]);
  const [live, setLive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scenarioRunId, setScenarioRunId] = useState<string | null>(null);
  const [scenarioStep, setScenarioStep] = useState(-1);
  const [scenarioRunning, setScenarioRunning] = useState(false);
  const [selectedAttack, setSelectedAttack] = useState<"SQL Injection" | "Prompt Injection" | "Log Injection" | null>(null);

  useEffect(() => {
    const refreshTimers = () => {
      getJson<Timer[]>("/api/timers")
        .then(setTimers)
        .catch((e: Error) => setError(e.message));
    };

    Promise.all([
      getJson<Stats>("/api/stats"),
      getJson<Event[]>(`/api/events?limit=${FEED_MAX}`),
      getJson<Rule[]>("/api/rules"),
    ])
      .then(([s, e, r]) => {
        setStats(s);
        setEvents(e);
        setRules(r);
      })
      .catch((e: Error) => setError(e.message));
    refreshTimers();
    const timerRefresh = window.setInterval(refreshTimers, 5000);

    let ws: WebSocket | null = null;
    let retry: number | undefined;
    let closed = false;
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${location.host}/ws/live`);
      ws.onopen = () => setLive(true);
      ws.onclose = () => {
        setLive(false);
        if (!closed) retry = window.setTimeout(connect, 2000); // analyst restarted: reconnect
      };
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data) as LiveMessage;
        if (msg.type === "event") setEvents((prev) => [msg.data, ...prev].slice(0, FEED_MAX));
        if (msg.type === "stats") setStats(msg.data);
        if (msg.type === "rule")
          setRules((prev) => {
            const rest = prev.filter((r) => r.id !== msg.data.id);
            return [...rest, msg.data];
          });
      };
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(retry);
      window.clearInterval(timerRefresh);
      ws?.close();
    };
  }, []);

  useEffect(() => {
    if (!scenarioRunning) return;
    let closed = false;
    const refreshScenario = async () => {
      try {
        const recent = await getJson<Event[]>(`/api/events?limit=${FEED_MAX}`);
        const completed = recent.reduce((highest, event) => {
          const step = event.scenario_step?.toLowerCase() ?? "";
          const index = SCENARIO_STEPS.findIndex(({ key, label }) => step.includes(key) || step.includes(label.toLowerCase()));
          return Math.max(highest, index);
        }, -1);
        if (closed || completed < 0) return;
        const nextStep = Math.min(completed + 1, SCENARIO_STEPS.length);
        setScenarioStep(nextStep);
        if (nextStep === SCENARIO_STEPS.length) setScenarioRunning(false);
      } catch (e) {
        if (!closed) setError(e instanceof Error ? e.message : "Unable to read scenario progress");
      }
    };
    refreshScenario();
    const progressRefresh = window.setInterval(refreshScenario, 1000);
    return () => {
      closed = true;
      window.clearInterval(progressRefresh);
    };
  }, [scenarioRunning]);

  const toggle = async (rule: Rule) => {
    const r = await fetch(`/api/rules/${encodeURIComponent(rule.id)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    if (!r.ok) setError(`toggle ${rule.id} → ${r.status}`);
    // the analyst pushes the updated rule over /ws/live
  };

  const runScenario = async () => {
    setError(null);
    setScenarioRunning(true);
    setScenarioRunId(null);
    setScenarioStep(0);
    try {
      const response = await fetch("/api/scenario/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ scenario: "full" }),
      });
      if (!response.ok) throw new Error(`/api/scenario/run → ${response.status}`);
      const result = (await response.json()) as { run_id: string };
      setScenarioRunId(result.run_id);
    } catch (e) {
      setScenarioRunning(false);
      setError(e instanceof Error ? e.message : "Unable to start scenario");
    }
  };

  const visibleEvents = selectedAttack
    ? events.filter((event) => {
        if (selectedAttack === "Log Injection") return event.owasp === "A09" || event.request.path.includes("memo");
        return event.owasp === "A05" || event.request.query.toLowerCase().includes(selectedAttack.split(" ")[0].toLowerCase());
      })
    : events;

  return (
    <div className="dashboard-shell">
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">EICAR · Security Feature Checks</p>
          <h1>Secure Sphere</h1>
          <p className="subtitle">Zero-day detection gateway · OWASP Top 10:2025</p>
        </div>
        <div className="header-actions">
          <span className={`live-pill ${live ? "is-live" : ""}`}>{live ? "● LIVE" : "○ CONNECTING"}</span>
          <a href="/slides/" className="ui-button">Slides</a>
          <a href="/honeypot/" className="ui-button">Honeypot</a>
        </div>
      </header>

      {error && <p className="error-banner">Analyst unreachable: {error}</p>}

      <main className="reference-layout">
        <nav className="attack-panel" aria-label="Security feature checks">
          {(["SQL Injection", "Prompt Injection", "Log Injection"] as const).map((attack) => (
            <button
              key={attack}
              type="button"
              className={`ui-button feature-box ${selectedAttack === attack ? "is-selected" : ""}`}
              onClick={() => {
                if (selectedAttack !== attack) fireAttacks(attack);
                setSelectedAttack(selectedAttack === attack ? null : attack);
              }}
            >
              {attack}
            </button>
          ))}
          <button type="button" className="ui-button feature-box clear-button" onClick={() => setSelectedAttack(null)}>
            Show All Events
          </button>
        </nav>

        <section className="evidence-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">OWASP security coverage</p>
              <h2>OWASP Top 10:2025</h2>
            </div>
            <button type="button" className="ui-button run-button" onClick={runScenario}>
              {scenarioRunning ? "Restart Scenario" : "Run Scenario"}
            </button>
          </div>
          <div className="owasp-center-grid">
            {(Object.keys(OWASP_2025) as OwaspId[]).map((id) => <OwaspTile key={id} id={id} counts={stats?.owasp[id]} />)}
          </div>
          <div className="evidence-heading">
            <span>{selectedAttack ?? "All traffic"} · live evidence</span>
            <span>{visibleEvents.length} events</span>
          </div>
          <div className="verdict-strip">
            {(["SAFE", "DIVERT", "DENY"] as Verdict[]).map((verdict) => (
              <div key={verdict} className={`verdict-card ${verdict.toLowerCase()}`}>
                <span>{verdict}</span>
                <strong>{stats?.totals[verdict] ?? 0}</strong>
              </div>
            ))}
          </div>
          <ol className="event-feed">
            {visibleEvents.length === 0 && <li className="empty-feed">Waiting for traffic… Select a check or run the scenario.</li>}
            {visibleEvents.map((event) => <FeedRow key={event.id} event={event} />)}
          </ol>
          <div className="scenario-progress">
            <div className="progress-heading">
              <span>{scenarioRunId ? `Run ${scenarioRunId}` : "Seven-step judge-facing flow"}</span>
              <span>{scenarioStep < 0 ? "Ready" : `${Math.min(scenarioStep, SCENARIO_STEPS.length)}/${SCENARIO_STEPS.length}`}</span>
            </div>
            <ol>
              {SCENARIO_STEPS.map((step, index) => (
                <li key={step.key} className={scenarioStep > index ? "complete" : scenarioRunning && scenarioStep === index ? "active" : ""}>
                  <span>{scenarioStep > index ? "✓" : index + 1}</span>{step.label}
                </li>
              ))}
            </ol>
          </div>
        </section>

        <aside className="info-panel">
          <div className="info-copy">
            {["EICAR", "AMTSO Security Feature Checks", "EMBER malware dataset", "CICMalDroid 2020"].map((item) => (
              <button key={item} type="button" className={`ui-button feature-box eicar-card ${item === "EICAR" ? "eicar-title" : ""}`}>
                {item}
              </button>
            ))}
          </div>
          <section className="info-section right-actions">
            <h2>First seen → blocked</h2>
            {timers.length === 0 ? <p className="muted">No learned rule has blocked yet.</p> : timers.map((timer) => (
              <div key={timer.rule_id} className="timer-card">
                <strong>{timer.seconds}s</strong>
                <span>{timer.rule_id} · {timer.owasp}</span>
              </div>
            ))}
          </section>
          <section className="info-section rules-section">
            <h2>Active rules <small>{stats?.learned_rules ?? 0} learned</small></h2>
            {rules.slice(0, 5).map((rule) => (
              <button key={rule.id} type="button" className={`ui-button rule-row ${rule.enabled ? "enabled" : ""}`} onClick={() => toggle(rule)} aria-pressed={rule.enabled}>
                <span>{rule.id} · {rule.owasp}</span><b>{rule.enabled ? "ON" : "OFF"}</b>
              </button>
            ))}
          </section>
        </aside>
      </main>
    </div>
  );
}

function FeedRow({ event: e }: { event: Event }) {
  const style = e.verdict ? VERDICT_STYLE[e.verdict] : "border-slate-600 bg-slate-800/40";
  return (
    <li className={`rounded-md border-l-4 px-3 py-2 ${style}`}>
      <div className="flex flex-wrap items-center gap-2">
        {e.verdict ? (
          <span className={`font-bold ${VERDICT_TEXT[e.verdict]}`}>{e.verdict}</span>
        ) : (
          // honeypot / sandbox events carry no verdict: show where they came from instead
          <span className="rounded bg-slate-700 px-2 text-sm font-semibold uppercase text-slate-200">{e.source}</span>
        )}
        {e.owasp && (
          <span className="rounded bg-slate-700 px-2 text-sm font-semibold" title={OWASP_2025[e.owasp]}>
            {e.owasp} · {OWASP_2025[e.owasp]}
          </span>
        )}
        {e.rule_id && <span className="font-mono text-sm text-slate-300">{e.rule_id}</span>}
        <span className="ml-auto text-sm text-slate-400">{new Date(e.ts).toLocaleTimeString()}</span>
      </div>
      <div className="mt-1 break-all font-mono text-base">
        {e.request.method} {e.request.path}
        {e.request.query && <span className="text-slate-400">?{e.request.query}</span>}
      </div>
    </li>
  );
}

function OwaspTile({ id, counts }: { id: OwaspId; counts?: { DIVERT: number; DENY: number } }) {
  const hits = (counts?.DIVERT ?? 0) + (counts?.DENY ?? 0);
  const slide = ON_SLIDE.includes(id);
  const lit = hits > 0 ? "border-red-500 bg-red-500/15" : "border-slate-700 bg-slate-800/50";
  return (
    <div className={`rounded-md border p-2 ${lit}`} title={OWASP_2025[id]}>
      <div className="flex items-baseline justify-between">
        <span className="text-lg font-bold">{id}</span>
        <span className="text-2xl font-bold tabular-nums">{hits}</span>
      </div>
      <div className="text-xs leading-tight text-slate-300">{OWASP_2025[id]}</div>
      {slide && <div className="mt-1 text-xs font-semibold uppercase text-sky-300">on slide</div>}
    </div>
  );
}
