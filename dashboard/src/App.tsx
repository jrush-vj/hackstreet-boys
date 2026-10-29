import { useEffect, useState } from "react";
import { MALWARE, OWASP_ATTACKS, type Attack } from "./attacks";
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
// Where the simulator sends attacks. Set only on the laptop (VITE_ATTACK_BASE); the homelab build leaves it
// unset, so visitors to graph.jrushvj.dev cannot fire attacks from the public dashboard.
const ATTACK_BASE: string | undefined = import.meta.env.VITE_ATTACK_BASE || undefined;
// the dashboard on graph.jrushvj.dev (slides and honeypot console links); override with VITE_DASHBOARD_BASE
const DASHBOARD_BASE: string = import.meta.env.VITE_DASHBOARD_BASE || "https://graph.jrushvj.dev";
const bytesOf = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
// the simulator's category buttons map to these paths in the corpus (SQL = search, prompt = chat, log = memo)
const CATEGORY_PATH: Record<"SQL Injection" | "Prompt Injection" | "Log Injection", string> = {
  "SQL Injection": "/search",
  "Prompt Injection": "/support/chat",
  "Log Injection": "/memo",
};
const MALWARE_CARDS = [
  ["EICAR", "eicar"],
  ["AMTSO Security Feature Checks", "script"],
  ["EMBER malware dataset", "exe"],
  ["CICMalDroid 2020", "apk"],
] as const;

// One click sends at most this many attacks, one after another, 400 ms apart.
const SENDS_PER_CLICK = 3;

// Sends up to SENDS_PER_CLICK requests in sequence and reports how many reached the gateway.
async function sendAll(list: Attack[], name: string, report: (msg: string) => void) {
  if (!ATTACK_BASE) {
    report("Attacks are sent from the laptop only: set VITE_ATTACK_BASE, then restart npm run dev.");
    return;
  }
  const base = ATTACK_BASE;
  const batch = list.slice(0, SENDS_PER_CLICK);
  report(`Sending ${batch.length} request(s) for ${name} to ${base} …`);
  let ok = 0;
  for (const [i, a] of batch.entries()) {
    if (i > 0) await new Promise((resolve) => setTimeout(resolve, 400));
    // no-cors: the browser only sends. The verdict is read on graph.jrushvj.dev, not here.
    const init: RequestInit = { method: a.method, mode: "no-cors" };
    if (a.zip) {
      init.body = bytesOf(MALWARE[a.zip].zipB64);
      init.headers = { "Content-Type": "text/plain" };
    } else if (a.body !== undefined) {
      init.body = a.body;
      init.headers = { "Content-Type": "text/plain" };
    }
    try {
      await fetch(base + a.path, init);
      ok++;
    } catch {
      // counted as failed below
    }
  }
  report(ok === batch.length
    ? `${name}: ${ok} request(s) sent. Watch graph.jrushvj.dev.`
    : `${name}: ${ok} of ${batch.length} reached ${base}; the rest failed (check the tunnel).`);
}

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
  const [status, setStatus] = useState<string | null>(null);
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

  const toggle = async (rule: Rule) => {
    const r = await fetch(`/api/rules/${encodeURIComponent(rule.id)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    if (!r.ok) setError(`toggle ${rule.id} → ${r.status}`);
    // the analyst pushes the updated rule over /ws/live
  };

  const visibleEvents = selectedAttack
    ? events.filter((event) => event.request.path.includes(CATEGORY_PATH[selectedAttack]))
    : events;

  return (
    <div className="dashboard-shell">
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">EICAR · Security Feature Checks</p>
          <h1>Secure Sphere</h1>
          <p className="subtitle">Zero-day detection gateway · 2025-26</p>
        </div>
        <div className="header-actions">
          <span className={`live-pill ${live ? "is-live" : ""}`}>{live ? "● LIVE" : "○ CONNECTING"}</span>
          <a href={`${DASHBOARD_BASE}/slides/`} className="ui-button">Slides</a>
          <a href={`${DASHBOARD_BASE}/honeypot/`} className="ui-button">Honeypot console</a>
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
                if (selectedAttack !== attack) sendAll(OWASP_ATTACKS.A05.filter((a) => a.path.includes(CATEGORY_PATH[attack])), attack, setStatus);
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
              <p className="eyebrow">2025-26 security coverage</p>
              <h2>2025-26</h2>
            </div>
          </div>
          <div className="owasp-center-grid">
            {(Object.keys(OWASP_2025) as OwaspId[]).map((id) => (
              <OwaspTile key={id} id={id} counts={stats?.owasp[id]} onFire={(oid) => sendAll(OWASP_ATTACKS[oid] ?? [], `${oid} ${OWASP_2025[oid]}`, setStatus)} />
            ))}
          </div>
          <div className="evidence-heading">
            <span>{selectedAttack ?? "All traffic"} · live evidence</span>
            <span>{visibleEvents.length} events</span>
          </div>
          {status && <p className="text-sm text-slate-300" role="status">{status}</p>}
          <div className="verdict-strip">
            {(["SAFE", "DIVERT", "DENY"] as Verdict[]).map((verdict) => (
              <div key={verdict} className={`verdict-card ${verdict.toLowerCase()}`}>
                <span>{verdict}</span>
                <strong>{stats?.totals[verdict] ?? 0}</strong>
              </div>
            ))}
          </div>
          <ol className="event-feed">
            {visibleEvents.length === 0 && <li className="empty-feed">Waiting for traffic… Click a check, a 2025-26 tile or a malware card.</li>}
            {visibleEvents.map((event) => <FeedRow key={event.id} event={event} />)}
          </ol>
        </section>

        <aside className="info-panel">
          <div className="info-copy">
            {MALWARE_CARDS.map(([item, key]) => (
              <button
                key={item}
                type="button"
                title={MALWARE[key].label}
                className={`ui-button feature-box eicar-card ${item === "EICAR" ? "eicar-title" : ""}`}
                onClick={() => sendAll([{ id: key, label: MALWARE[key].label, method: "POST", path: "/api/statements/upload", zip: key }], item, setStatus)}
              >
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

function OwaspTile({ id, counts, onFire }: { id: OwaspId; counts?: { DIVERT: number; DENY: number }; onFire: (id: OwaspId) => void }) {
  const hits = (counts?.DIVERT ?? 0) + (counts?.DENY ?? 0);
  const slide = ON_SLIDE.includes(id);
  const lit = hits > 0 ? "border-red-500 bg-red-500/15" : "border-slate-700 bg-slate-800/50";
  return (
    <button type="button" onClick={() => onFire(id)} title={`Send the ${OWASP_2025[id]} attacks`} className={`rounded-md border p-2 text-left ${lit}`}>
      <div className="flex items-baseline justify-between">
        <span className="text-lg font-bold">{id}</span>
        <span className="text-2xl font-bold tabular-nums">{hits}</span>
      </div>
      <div className="text-xs leading-tight text-slate-300">{OWASP_2025[id]}</div>
      {slide && <div className="mt-1 text-xs font-semibold uppercase text-sky-300">on slide</div>}
    </button>
  );
}
