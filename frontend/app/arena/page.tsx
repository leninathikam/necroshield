"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { SourceText } from "@/components/SourceText";
import { Load } from "@/components/States";
import { api } from "@/lib/api";
import { argsText } from "@/lib/events";
import type { McpReplay, Mode, ScenarioView } from "@/lib/types";
import { useApi } from "@/lib/useApi";

type Target = "fixture" | "mcp";

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

  async function launch(id: string) {
    setBusy(true);
    setError("");
    setMcp(null);
    try {
      if (target === "fixture") {
        const run = await api.startRun(id);
        router.push(`/replay/?pair=${run.summary.pair_id}`);
      } else {
        setMcp(await api.mcpReplay(id, mode));
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
                    <option value="live" disabled>
                      Live model (operator-only; see note below)
                    </option>
                  </select>
                </label>
                {target === "mcp" && (
                  <label>
                    Gateway
                    <select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
                      <option value="protected">protected</option>
                      <option value="baseline">baseline</option>
                    </select>
                  </label>
                )}
                <button className="btn btn-primary" onClick={() => launch(id)} disabled={busy}>
                  {busy ? "Running…" : "Launch simulation"}
                </button>
              </div>
              {live.state === "ready" && (
                <p className="faint">
                  Live agent evaluation: {live.data.reason}. Paid model runs are started by the operator from the
                  server shell, never from this page; their exports can be checked in the Evidence Explorer. Results
                  here are deterministic_intent_replay.
                </p>
              )}
              {error && <p role="alert" className="state state-error">Launch failed: {error}</p>}
              {mcp && <McpTranscript result={mcp} />}
              <ScenarioDetail s={s} />
            </div>
          );
        }}
      </Load>
    </>
  );
}
