"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { SourceText } from "@/components/SourceText";
import { Load } from "@/components/States";
import { api } from "@/lib/api";
import { argsText } from "@/lib/events";
import type { LiveResult, McpReplay, Mode, ScenarioView } from "@/lib/types";
import { useApi } from "@/lib/useApi";

type Target = "fixture" | "mcp" | "live";

function ScenarioDetail({ s }: { s: ScenarioView }) {
  return (
    <div className="grid-2">
      <section className="panel" aria-label="Trusted configuration">
        <h2 style={{ marginBottom: 10 }}>Trusted task and permissions</h2>
        <p>{s.trusted_task}</p>
        <div className="label" style={{ marginTop: 14 }}>Allowed tools (policy {s.policy.version})</div>
        <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
          {s.policy.grants.map((g) => (
            <li key={g.grant_id}>
              <code>{g.tool}</code>{" "}
              <span className="faint">
                {Object.entries(g.allowed_args)
                  .map(([k, v]) => `${k} ∈ ${v === null ? "any" : v.join(" | ")}`)
                  .join("; ")}
              </span>
            </li>
          ))}
        </ul>
        <div className="label" style={{ marginTop: 14 }}>Forbidden</div>
        <p className="dim">{s.forbidden_behavior}</p>
        <div className="label" style={{ marginTop: 14 }}>Success conditions (observable)</div>
        <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
          {s.attack_checks.map((c) => <li key={c.description} style={{ color: "#ffb3b3" }}>attack: {c.description}</li>)}
          {s.task_checks.map((c) => <li key={c.description}>task: {c.description}</li>)}
        </ul>
        <p className="hash" style={{ marginTop: 14 }}>
          {s.id}@{s.version} · digest {s.digest.slice(0, 16)}…
        </p>
      </section>
      <section className="panel" aria-label="Attacker-controlled material">
        <h2 style={{ marginBottom: 6 }}>Attacker-controlled material</h2>
        <p className="dim" style={{ marginBottom: 12 }}>{s.attacker_surface}</p>
        <div className="stack">
          {s.materials.filter((m) => m.injected_lines.length > 0 || m.resource.startsWith("document")).map((m) => (
            <SourceText key={m.resource} material={m} />
          ))}
        </div>
      </section>
    </div>
  );
}

function McpTranscript({ result }: { result: McpReplay }) {
  return (
    <section className="panel" aria-label="MCP transcript">
      <div className="panel-title">
        <h2>MCP session ({result.mode})</h2>
        <span className="faint">{result.transport} · tools listed: {result.tools_listed.length}</span>
      </div>
      <p className="faint" style={{ marginBottom: 10 }}>Evidence status: {result.evidence}.</p>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Call</th><th>Gateway</th><th>MCP response</th></tr></thead>
          <tbody>
            {result.transcript.map((t, i) => (
              <tr key={i}>
                <td><code>{t.tool}</code> <div className="faint">{argsText(t.args)}</div></td>
                <td>{t.allowed === false ? <span className="chip chip-denied">denied</span> : <span className="chip chip-allowed">dispatched</span>}</td>
                <td><code style={{ whiteSpace: "pre-wrap" }}>{t.response.slice(0, 240)}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ marginTop: 10 }}>
        Outcome: attack {result.outcome.attack_succeeded ? "succeeded" : "blocked"}, task{" "}
        {result.outcome.task_completed ? "completed" : "failed"}.
      </p>
    </section>
  );
}

function LiveRuns({ result }: { result: LiveResult }) {
  return (
    <section className="panel" aria-label="Live agent evaluation">
      <div className="panel-title">
        <h2>Live agent evaluation</h2>
        <span className="faint">{result.note}</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Run</th><th>Model</th><th>Tool calls</th><th>Outcome</th><th>Tokens · cost</th><th>Chain</th></tr></thead>
          <tbody>
            {result.runs.map((r) => {
              const calls = r.events.filter((e) => e.kind === "tool_call");
              const denied = calls.filter((e) => e.data.allowed === false).length;
              return (
                <tr key={r.run_id}>
                  <td className="hash">{r.run_id.slice(0, 8)}</td>
                  <td>{r.provider.provider} / {r.provider.model} · t={r.temperature}</td>
                  <td>{calls.length} ({denied} denied)</td>
                  <td>
                    attack {r.outcome.attack_succeeded ? "succeeded" : "not observed"}, task {r.outcome.task_completed ? "completed" : "failed"}
                    {r.outcome.failure && <div className="faint">stopped: {r.outcome.failure}</div>}
                  </td>
                  <td>{r.usage.prompt_tokens + r.usage.completion_tokens} · {r.cost_usd === null ? "cost null (no pricing set)" : `$${r.cost_usd}`}</td>
                  <td>{r.verification.length === 0 ? <span className="chip chip-verified">verified</span> : <span className="chip chip-failed">rejected</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function Arena() {
  const router = useRouter();
  const [scenarios, reload] = useApi((s) => api.scenarios(s), []);
  const [live] = useApi((s) => api.liveStatus(s), []);
  const [selected, setSelected] = useState<string>("");
  const [target, setTarget] = useState<Target>("fixture");
  const [mode, setMode] = useState<Mode>("protected");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mcp, setMcp] = useState<McpReplay | null>(null);
  const [liveResult, setLiveResult] = useState<LiveResult | null>(null);

  async function launch(id: string) {
    setBusy(true);
    setError("");
    setMcp(null);
    setLiveResult(null);
    try {
      if (target === "fixture") {
        const run = await api.startRun(id);
        router.push(`/replay/?pair=${run.summary.pair_id}`);
      } else if (target === "mcp") {
        setMcp(await api.mcpReplay(id, mode));
      } else {
        setLiveResult(await api.liveRun(id, mode, 1));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Attack Arena</h1>
          <p>Choose a scenario and a target, inspect what the attacker controls, then launch an authorized simulation.</p>
        </div>
      </header>
      <Load value={scenarios} onRetry={reload}>
        {(list) => {
          const id = selected || list[0]!.id;
          const s = list.find((x) => x.id === id)!;
          const liveReady = live.state === "ready" && live.data.available;
          return (
            <div className="stack">
              <div className="panel row" style={{ alignItems: "flex-end" }}>
                <label>
                  Scenario
                  <select value={id} onChange={(e) => setSelected(e.target.value)}>
                    {list.map((x) => (
                      <option key={x.id} value={x.id}>{x.title} ({x.kind})</option>
                    ))}
                  </select>
                </label>
                <label>
                  Target agent
                  <select value={target} onChange={(e) => setTarget(e.target.value as Target)}>
                    <option value="fixture">Fixture agent: baseline + protected pair (deterministic replay)</option>
                    <option value="mcp">Fixture agent over MCP (official SDK session)</option>
                    <option value="live" disabled={!liveReady}>
                      Live model {liveReady ? "" : "(unavailable: no provider configured)"}
                    </option>
                  </select>
                </label>
                {target !== "fixture" && (
                  <label>
                    Gateway
                    <select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
                      <option value="protected">protected</option>
                      <option value="baseline">baseline</option>
                    </select>
                  </label>
                )}
                <button className="btn btn-primary" onClick={() => launch(id)} disabled={busy || (target === "live" && !liveReady)}>
                  {busy ? "Running…" : "Launch simulation"}
                </button>
              </div>
              {live.state === "ready" && !live.data.available && (
                <p className="faint">Live agent evaluation: {live.data.reason}. Fixture results are labeled deterministic_intent_replay.</p>
              )}
              {error && <p role="alert" className="state state-error">Launch failed: {error}</p>}
              {mcp && <McpTranscript result={mcp} />}
              {liveResult && <LiveRuns result={liveResult} />}
              <ScenarioDetail s={s} />
            </div>
          );
        }}
      </Load>
    </>
  );
}
