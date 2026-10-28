import { useEffect, useState } from "react";
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

  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Secure Sphere</h1>
          <p className="text-base text-slate-400">Zero-day detection gateway · OWASP Top 10:2025</p>
        </div>
        <span className={`rounded-full px-3 py-1 text-sm font-semibold ${live ? "bg-emerald-500/20 text-emerald-300" : "bg-slate-800 text-slate-400"}`}>
          {live ? "● live" : "○ connecting…"}
        </span>
      </header>

      {error && <p className="bg-red-900/40 px-6 py-2 text-red-200">Analyst unreachable: {error}</p>}

      <main className="grid gap-4 p-4 lg:grid-cols-[3fr_2fr]">
        <section className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 className="mb-3 text-xl font-semibold">Live feed</h2>
          <ol className="max-h-[75vh] space-y-2 overflow-y-auto pr-1">
            {events.length === 0 && <li className="text-slate-400">Waiting for traffic…</li>}
            {events.map((e) => (
              <FeedRow key={e.id} event={e} />
            ))}
          </ol>
        </section>

        <aside className="space-y-4">
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 className="mb-3 text-xl font-semibold">Totals</h2>
            <div className="grid grid-cols-3 gap-2">
              {(["SAFE", "DIVERT", "DENY"] as Verdict[]).map((v) => (
                <div key={v} className={`rounded-md border-l-4 p-3 ${VERDICT_STYLE[v]}`}>
                  <div className={`text-sm font-semibold ${VERDICT_TEXT[v]}`}>{v}</div>
                  <div className="text-3xl font-bold tabular-nums">{stats?.totals[v] ?? 0}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 className="mb-3 text-xl font-semibold">OWASP Top 10:2025</h2>
            <div className="grid grid-cols-2 gap-2 xl:grid-cols-5">
              {(Object.keys(OWASP_2025) as OwaspId[]).map((id) => (
                <OwaspTile key={id} id={id} counts={stats?.owasp[id]} />
              ))}
            </div>
          </section>

          <section className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 className="mb-3 text-xl font-semibold">
              Rules <span className="text-base font-normal text-slate-400">({stats?.learned_rules ?? 0} learned)</span>
            </h2>
            <ul className="max-h-64 divide-y divide-slate-800 overflow-y-auto">
              {rules.map((r) => (
                <li key={r.id} className={`flex items-center justify-between gap-3 py-2 ${r.source === "learned" ? "text-amber-200" : ""}`}>
                  <div className="min-w-0">
                    <div className="font-mono text-sm font-semibold">
                      {r.id} · {r.owasp} · {r.action} {r.source === "learned" && "· learned"}
                    </div>
                    <div className="truncate text-sm text-slate-400">{r.description}</div>
                  </div>
                  <button
                    onClick={() => toggle(r)}
                    className={`shrink-0 rounded px-3 py-1 text-sm font-semibold ${r.enabled ? "bg-emerald-600 text-white" : "bg-slate-700 text-slate-300"}`}
                    aria-pressed={r.enabled}
                  >
                    {r.enabled ? "On" : "Off"}
                  </button>
                </li>
              ))}
            </ul>
          </section>

          <section className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 className="mb-3 text-xl font-semibold">First seen → blocked</h2>
            {timers.length === 0 ? (
              <p className="text-slate-400">No learned rule has blocked yet.</p>
            ) : (
              timers.map((t) => (
                <div key={t.rule_id} className="mb-3 text-lg last:mb-0">
                  <div>
                    <span className="text-4xl font-bold tabular-nums text-amber-300">{t.seconds}s</span>{" "}
                    <span className="font-mono">{t.rule_id}</span> ({t.owasp})
                  </div>
                  <div className="text-sm text-slate-400">
                    First blocked {new Date(t.first_blocked).toLocaleTimeString()}
                  </div>
                </div>
              ))
            )}
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
