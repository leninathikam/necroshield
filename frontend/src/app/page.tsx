"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, BookOpen, Check,
  ChevronDown, ChevronRight, CircleAlert, Clock3, Database, FlaskConical,
  History, Layers3, LoaderCircle, Menu, Play, Radar, RefreshCw, ShieldCheck,
  ShieldHalf, SlidersHorizontal, Terminal, X,
} from "lucide-react";
import { AttackGraph } from "@/components/AttackGraph";
import { Comparison } from "@/components/Comparison";
import { Inspector } from "@/components/Inspector";
import { Timeline } from "@/components/Timeline";
import { api } from "@/lib/api";
import type { Pair, PairSummary, Run, Scenario, TraceEvent } from "@/lib/types";

type View = "arena" | "registry" | "history" | "benchmarks";
type Benchmark = {
  id: string; created_at: string; execution_kind: string; total_scenarios: number;
  attack_scenarios: number; control_scenarios: number; baseline_attack_success_rate: number;
  protected_attack_success_rate: number; protected_task_completion_rate: number;
  false_positive_rate: number; blocked_executions: number; latency_ms: number;
  cost_usd: number | null; pair_ids: string[];
};
const navigation = [
  { id: "arena" as const, label: "Attack arena", icon: Radar },
  { id: "registry" as const, label: "Scenario registry", icon: Layers3 },
  { id: "history" as const, label: "Run archive", icon: History },
  { id: "benchmarks" as const, label: "Benchmarks", icon: Activity },
];
const titles = {
  arena: ["Attack arena", "Test the agent. Trust the evidence."],
  registry: ["Scenario registry", "Versioned threats. Strictly synthetic."],
  history: ["Run archive", "Every decision leaves a trace."],
  benchmarks: ["Benchmarks", "Security means little without utility."],
};

function relativeDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));
}
function percentage(value: number) { return `${(value * 100).toFixed(0)}%`; }

export default function Dashboard() {
  const [view, setView] = useState<View>("arena");
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [history, setHistory] = useState<PairSummary[]>([]);
  const [scenarioId, setScenarioId] = useState("");
  const [pair, setPair] = useState<Pair | null>(null);
  const [selected, setSelected] = useState<{ event: TraceEvent; mode: Run["mode"] } | null>(null);
  const [timelineMode, setTimelineMode] = useState<Run["mode"]>("protected");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState<"run" | "benchmark" | "history" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [benchmark, setBenchmark] = useState<Benchmark | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [items, runs] = await Promise.all([api<Scenario[]>("/scenarios"), api<PairSummary[]>("/runs")]);
      setScenarios(items); setHistory(runs); setConnected(true);
      setScenarioId(current => current || items[0]?.id || "");
    } catch (cause) { setConnected(false); setError(cause instanceof Error ? cause.message : "Unable to reach the arena API."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!menuOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") setMenuOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [menuOpen]);
  const scenario = scenarios.find(item => item.id === scenarioId);

  function chooseScenario(id: string) {
    setScenarioId(id); setPair(null); setSelected(null);
  }

  async function launch() {
    if (!scenarioId || working) return;
    setWorking("run"); setError(null); setView("arena");
    try {
      const result = await api<Pair>("/runs", { method: "POST", body: JSON.stringify({ scenario_id: scenarioId }) });
      setPair(result); setTimelineMode("protected");
      const decision = result.protected.events.find(event => event.decision === "deny") || result.protected.events[0];
      setSelected(decision ? { event: decision, mode: "protected" } : null);
      setHistory(await api<PairSummary[]>("/runs"));
    } catch (cause) { setError(cause instanceof Error ? cause.message : "The run could not be completed."); }
    finally { setWorking(null); }
  }
  async function openRun(id: string) {
    setWorking("history"); setError(null);
    try {
      const result = await api<Pair>(`/runs/${encodeURIComponent(id)}`);
      setPair(result); setScenarioId(result.scenario_id); setSelected(null); setView("arena");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load this run."); }
    finally { setWorking(null); }
  }
  async function runBenchmark() {
    setWorking("benchmark"); setError(null);
    try {
      setBenchmark(await api<Benchmark>("/benchmarks", { method: "POST" }));
      setHistory(await api<PairSummary[]>("/runs"));
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Benchmark did not complete."); }
    finally { setWorking(null); }
  }
  function selectEvent(event: TraceEvent, mode: Run["mode"]) { setSelected({ event, mode }); setTimelineMode(mode); }
  const protectedMetrics = pair?.protected.metrics;

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to main content</a>
    {menuOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />}
    <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
      <a href="/" className="brand" aria-label="NecroShield home"><div className="brand-symbol"><ShieldHalf size={25} strokeWidth={1.6} /><span /></div><span>NECRO<span className="brand-light">SHIELD</span><small>AGENT SECURITY ARENA</small></span></a>
      <button className="mobile-close icon-button" aria-label="Close navigation" onClick={() => setMenuOpen(false)}><X size={19} /></button>
      <div className="workspace-card"><span className="workspace-avatar"><FlaskConical size={17} /></span><div><strong>Synthetic laboratory</strong><span>Local workspace</span></div><ChevronDown size={14} /></div>
      <div className="nav-caption">COMMAND CENTER</div>
      <nav aria-label="Main navigation">{navigation.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${view === id ? "active" : ""}`} aria-current={view === id ? "page" : undefined} onClick={() => { setView(id); setMenuOpen(false); }}><Icon size={18} /><span>{label}</span>{view === id && <ChevronRight size={14} />}</button>)}</nav>
      <div className="sidebar-spacer" />
      <div className="scope-card"><span className="scope-icon"><ShieldCheck size={18} /></span><strong>Contained by design.</strong><p>Inert fixtures. Synthetic records.<br />No external attack targets.</p><span className="scope-tag"><i />SYNTHETIC SCOPE</span></div>
      <div className="sidebar-footer"><span className="dot violet" /><span>NECROSHIELD <b>v0.1</b></span><ArrowUpRight size={13} /></div>
    </aside>

    <div className="main-shell">
      <header className="topbar"><button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMenuOpen(true)}><Menu size={20} /></button><div className="breadcrumb">WORKSPACE <ChevronRight size={11} /><span>{titles[view][0]}</span></div><div className="topbar-right"><span className={`connection ${connected ? "online" : ""}`}><i />{loading ? "Connecting" : connected ? "API connected" : "API unavailable"}</span><span className="topbar-divider" /><span className="mono topbar-mode">SYNTHETIC / DETERMINISTIC</span></div></header>
      <main id="main-content">
        <div className="page-heading"><div><div className="eyebrow"><span className="heading-line" />OBSERVE. INTERCEPT. VERIFY.</div><h1>{titles[view][0]}<span className="title-period">.</span></h1><p>{titles[view][1]}</p></div><div className="page-heading-right"><span className="lab-badge"><FlaskConical size={14} />FIXTURE EXECUTION</span><span className="muted tiny">No LLM evaluation configured</span></div></div>

        {error && <div className="error-banner" role="alert"><CircleAlert size={18} /><div><strong>Unable to complete request</strong><span>{error}. Check that the FastAPI service is running on port 8017.</span></div><button className="secondary-button" onClick={() => void refresh()} disabled={loading}><RefreshCw size={14} />Retry</button></div>}

        {view === "arena" && <>
          <section className="command-bar" aria-label="Scenario controls"><div className="scenario-control"><span className="scenario-control-icon"><Layers3 size={19} /></span><div><label htmlFor="scenario-select">SCENARIO</label><div className="select-wrap"><select id="scenario-select" value={scenarioId} onChange={event => chooseScenario(event.target.value)} disabled={loading || !!working || !scenarios.length}>{!scenarios.length && <option>{loading ? "Loading scenario registry…" : "No scenarios available"}</option>}{scenarios.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select><ChevronDown size={14} /></div></div></div><span className="scenario-version">{scenario ? `v${scenario.version}` : "—"}</span><span className="command-divider" /><div className="replay-label"><span className="eyebrow">REPLAY MODE</span><span>Identical intent tape <BookOpen size={12} /></span></div><button className="primary-button launch-button" disabled={!scenarioId || !!working || loading || !connected} onClick={() => void launch()}>{working === "run" ? <LoaderCircle size={16} className="spin" /> : <Play size={15} fill="currentColor" />}{working === "run" ? "Executing paired run…" : "Launch paired run"}</button></section>
          <div className="scenario-description"><span className="dot amber" />{scenario?.description || "Load the registry to choose a controlled security experiment."}</div>

          <section className="metric-grid" aria-label="Protected run measurements">
            <Metric label="ATTACK EFFECT" value={pair ? protectedMetrics?.attack_success ? "Observed" : "Contained" : "—"} detail={pair ? "Verified from sandbox state" : "Awaiting first execution"} icon={ShieldCheck} tone={pair && protectedMetrics?.attack_success ? "amber" : "violet"} />
            <Metric label="BLOCKED EXECUTIONS" value={protectedMetrics?.blocked_executions.toString() ?? "—"} detail="Denied before tool dispatch" icon={SlidersHorizontal} />
            <Metric label="LEGITIMATE TASK" value={pair ? protectedMetrics?.legitimate_task_completed ? "Complete" : "Incomplete" : "—"} detail="Measured separately from security" icon={Check} />
            <Metric label="FALSE POSITIVES" value={protectedMetrics?.false_positives.toString() ?? "—"} detail={pair ? `${protectedMetrics?.tool_calls} tools executed · ${protectedMetrics?.latency_ms.toFixed(2)} ms` : "No measurements yet"} icon={Activity} />
          </section>

          <div className="arena-grid"><section className="panel graph-panel"><div className="panel-header"><h2><Radar size={16} />Counterfactual attack graph</h2><div className="graph-legend"><span><i className="dot amber" />Baseline</span><span><i className="dot violet" />Protected</span></div></div><AttackGraph pair={pair} selected={selected ? { mode: selected.mode, sequence: selected.event.sequence } : null} onSelect={selectEvent} /><div className="graph-footer"><span><span className="dot muted-dot" />{pair ? "Persisted decision trace" : "No run selected"}</span><span>{pair ? `PAIR ${pair.id.slice(0, 8).toUpperCase()}` : "POLICY BOUNDARY / DEFAULT DENY"}</span></div></section><Inspector event={selected?.event || null} mode={selected?.mode || "protected"} /></div>

          <section className="panel comparison-panel"><div className="panel-header"><h2><ShieldHalf size={16} />The same intent. Two outcomes.</h2><span className="muted tiny">Deterministic counterfactual replay</span></div><Comparison pair={pair} /></section>

          <section className="panel timeline-panel"><div className="panel-header"><h2><Clock3 size={16} />Execution timeline</h2>{pair && <div className="segmented" aria-label="Timeline run mode">{(["baseline", "protected"] as const).map(mode => <button key={mode} aria-pressed={timelineMode === mode} className={timelineMode === mode ? "active" : ""} onClick={() => setTimelineMode(mode)}>{mode}</button>)}</div>}</div>{pair ? <Timeline run={pair[timelineMode]} selected={selected?.mode === timelineMode ? selected.event.sequence : undefined} onSelect={event => selectEvent(event, timelineMode)} /> : <div className="timeline-placeholder"><span className="timeline-placeholder-line" /><span>Events appear here after execution.</span><span className="timeline-placeholder-line" /></div>}</section>
          {pair && <div className="evidence-strip"><div><Database size={16} /><span>Evidence is retained with versioned scenarios and a hash-linked event trace.</span></div><a className="text-button" href={`/api/runs/${pair.id}/export`} download><ArrowDownToLine size={15} />Export redacted evidence</a></div>}
        </>}

        {view === "registry" && <section aria-label="Available scenarios"><div className="section-intro"><span className="eyebrow">{scenarios.length} VERSIONED SCENARIOS</span><span className="muted tiny">Controlled inputs · in-memory effects</span></div>{loading ? <LoadingState text="Loading scenario registry" /> : scenarios.length ? <div className="registry-grid">{scenarios.map((item, index) => <article className="panel registry-card" key={item.id}><div className="registry-card-top"><span className="registry-number">{String(index + 1).padStart(2, "0")}</span><span className={`severity ${item.severity.toLowerCase()}`}>{item.severity}</span></div><span className="eyebrow">{item.category.replaceAll("_", " ")}</span><h2>{item.name}</h2><p>{item.description}</p><div className="registry-task"><span className="eyebrow">LEGITIMATE TASK</span><p>{item.task}</p></div><div className="registry-card-bottom"><span className="mono muted">v{item.version}</span><button className="text-button" onClick={() => { chooseScenario(item.id); setView("arena"); }}>Open in arena<ArrowRight size={14} /></button></div></article>)}</div> : <EmptyState icon={Layers3} title="No scenarios loaded" description="The registry is unavailable. Start the backend, then reconnect to load the versioned fixtures." />}</section>}

        {view === "history" && <section className="panel archive-panel"><div className="panel-header"><h2><History size={16} />Persisted paired runs</h2><button className="text-button" onClick={() => void refresh()} disabled={loading}><RefreshCw size={14} />Refresh</button></div>{loading ? <LoadingState text="Loading run archive" /> : history.length ? <div className="history-list">{history.map(item => <div className="history-row" key={item.id}><span className="history-icon"><ShieldHalf size={18} /></span><div className="history-info"><strong>{item.scenario_name}</strong><span className="mono">{item.id}</span></div><time dateTime={item.created_at}>{relativeDate(item.created_at)}</time><a className="icon-button" aria-label={`Export ${item.scenario_name} evidence`} href={`/api/runs/${item.id}/export`} download><ArrowDownToLine size={16} /></a><button className="secondary-button" onClick={() => void openRun(item.id)} disabled={!!working}>Inspect<ArrowUpRight size={14} /></button></div>)}</div> : <EmptyState icon={History} title="A clean slate." description="Run your first scenario in the attack arena. Its paired traces and evidence will be retained here." action={() => setView("arena")} actionLabel="Go to attack arena" />}</section>}

        {view === "benchmarks" && <>
          <section className="panel benchmark-hero"><div className="benchmark-symbol"><Activity size={32} strokeWidth={1.2} /></div><div><span className="eyebrow">REGISTRY-WIDE EVALUATION</span><h2>Measure the boundary.</h2><p>Execute every scenario in fresh baseline and protected sandboxes. Attack effects and legitimate task completion are evaluated from actual state.</p></div><button className="primary-button" onClick={() => void runBenchmark()} disabled={!!working || !connected || !scenarios.length}>{working === "benchmark" ? <LoaderCircle className="spin" size={16} /> : <Play size={15} fill="currentColor" />}{working === "benchmark" ? "Evaluating registry…" : "Run benchmark"}</button></section>
          {benchmark ? <><div className="benchmark-metadata"><span className="mono">BENCHMARK {benchmark.id.slice(0, 8).toUpperCase()}</span><span>{relativeDate(benchmark.created_at)} · {benchmark.total_scenarios} scenarios · {benchmark.latency_ms.toFixed(2)} ms</span></div><div className="metric-grid"><Metric label="BASELINE ATTACK SUCCESS" value={percentage(benchmark.baseline_attack_success_rate)} detail={`${benchmark.attack_scenarios} attack scenarios`} icon={Activity} tone="amber" /><Metric label="PROTECTED ATTACK SUCCESS" value={percentage(benchmark.protected_attack_success_rate)} detail="Effect-based evaluation" icon={ShieldCheck} /><Metric label="TASK COMPLETION" value={percentage(benchmark.protected_task_completion_rate)} detail="Protected legitimate task utility" icon={Check} /><Metric label="FALSE POSITIVE RATE" value={percentage(benchmark.false_positive_rate)} detail="Authorized legitimate calls" icon={SlidersHorizontal} /></div><div className="panel benchmark-results"><div className="panel-header"><h2><Terminal size={16} />Reproducible result</h2><span className="lab-badge">DETERMINISTIC FIXTURE</span></div><dl><div><dt>Blocked before dispatch</dt><dd>{benchmark.blocked_executions} executions</dd></div><div><dt>Model API cost</dt><dd>{benchmark.cost_usd === null ? "Not measured · no model calls" : `$${benchmark.cost_usd.toFixed(4)}`}</dd></div><div><dt>Independent run pairs</dt><dd>{benchmark.pair_ids.length}</dd></div></dl><p className="benchmark-note">These measurements describe the published synthetic fixtures. They do not estimate attack success against a stochastic language model or establish a production security guarantee.</p><button className="text-button" onClick={() => setView("history")}>Inspect the benchmark run pairs<ArrowRight size={14} /></button></div></> : <EmptyState icon={FlaskConical} title="Evidence before averages." description="No benchmark has been executed in this session. Run the registry to produce measured results; no scores are pre-populated." />}
        </>}
        <footer className="main-footer"><span><ShieldHalf size={12} />AUTHORIZED SYNTHETIC ENVIRONMENTS ONLY</span><span>Security outcomes are observed. Model behavior is not inferred.</span></footer>
      </main>
    </div>
  </div>;
}

function Metric({ label, value, detail, icon: Icon, tone = "violet" }: { label: string; value: string; detail: string; icon: typeof Activity; tone?: string }) {
  return <article className={`metric-card ${tone}`}><div><span className="eyebrow">{label}</span><Icon size={16} /></div><strong>{value}</strong><p>{detail}</p></article>;
}
function EmptyState({ icon: Icon, title, description, action, actionLabel }: { icon: typeof Activity; title: string; description: string; action?: () => void; actionLabel?: string }) {
  return <div className="empty-state"><span className="empty-state-icon"><Icon size={29} strokeWidth={1.1} /></span><h2>{title}</h2><p>{description}</p>{action && <button className="secondary-button" onClick={action}>{actionLabel}<ArrowRight size={14} /></button>}</div>;
}
function LoadingState({ text }: { text: string }) { return <div className="loading-state" role="status"><LoaderCircle size={21} className="spin" />{text}…</div>; }
