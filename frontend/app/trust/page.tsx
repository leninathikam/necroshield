"use client";

import { useRef, useState } from "react";
import { Load } from "@/components/States";
import { api } from "@/lib/api";
import type { Inspection, ManifestChange } from "@/lib/types";
import { useApi } from "@/lib/useApi";

function Change({ c }: { c: ManifestChange }) {
  const cls = c.severity === "escalation" ? "chip-failed" : c.severity === "reduction" ? "chip-allowed" : "chip-denied";
  return (
    <li style={{ marginBottom: 10 }}>
      <span className={`chip ${cls}`}>{c.severity}</span> <code>{c.tool}</code> · {c.kind.replaceAll("_", " ")}
      <div>{c.summary}</div>
      {c.diff && c.diff.length > 0 && (
        <pre className="source" style={{ marginTop: 6 }}>
          {c.diff.map((line, i) => (
            <span key={i} style={{ color: line.startsWith("+") ? "#ffb3b3" : line.startsWith("-") ? "#9fd6b5" : undefined }}>
              {line + "\n"}
            </span>
          ))}
        </pre>
      )}
    </li>
  );
}

export default function TrustPage() {
  const [info, reload] = useApi((s) => api.manifest(s), []);
  const [drift, setDrift] = useState("");
  const [result, setResult] = useState<Inspection | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);

  async function inspect(approve?: string) {
    // A late response from an earlier inspection must never replace a newer one, and approving
    // always re-inspects the drift that produced the result on screen, not whatever is selected now.
    const mine = ++generation.current;
    const target = approve && result ? result.drift : drift || null;
    setBusy(true);
    setError("");
    try {
      const next = await api.inspect(target, approve);
      if (mine === generation.current) setResult(next);
    } catch (e) {
      if (mine === generation.current) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (mine === generation.current) setBusy(false);
    }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>MCP Trust</h1>
          <p>
            The sandbox&apos;s tool definitions are hashed and compared with an approved manifest. A changed description, a new
            argument, a new tool, or a new capability is shown as a readable diff and refused until a person approves that exact
            manifest. Only NecroShield&apos;s own synthetic sandbox is inspected; no external server is contacted.
          </p>
        </div>
      </header>
      <Load value={info} onRetry={reload}>
        {(m) => (
          <div className="stack">
            <section className="panel">
              <div className="panel-title">
                <h2>Approved manifest</h2>
                <span className="hash">digest {m.approved.digest.slice(0, 20)}…</span>
              </div>
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Approved synthetic tools</caption>
                  <thead>
                    <tr><th>Tool</th><th>Arguments</th><th>Effects</th><th>Egress</th><th>Hash</th></tr>
                  </thead>
                  <tbody>
                    {m.approved.tools.map((t) => (
                      <tr key={t.name}>
                        <td><code>{t.name}</code></td>
                        <td className="mono">{Object.entries(t.input.properties).map(([k, v]) => `${k}: ${v}`).join(", ")}</td>
                        <td>{t.capabilities.effects.join(", ")}</td>
                        <td>{t.capabilities.egress}</td>
                        <td className="hash">{t.hash.slice(0, 12)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="panel">
              <h2 style={{ marginBottom: 8 }}>Inspect the live sandbox</h2>
              <p className="dim" style={{ marginBottom: 10 }}>
                Reads <code>tools/list</code> from the sandbox&apos;s MCP server and compares it with the approved manifest. Pick a
                synthetic drift to see what the sandbox would advertise if its definitions changed. MCP does not advertise capabilities:
                the capability column is NecroShield&apos;s own annotation, and the capability example is a mutation applied by the server.
                Approval here is a request parameter for demonstration: it is simulated, covers one digest, and is not persisted.
              </p>
              <p className="row" style={{ alignItems: "flex-end" }}>
                <label>
                  Synthetic drift
                  <select
                    aria-label="Synthetic drift"
                    value={drift}
                    onChange={(e) => {
                      generation.current++;
                      setDrift(e.target.value);
                      setResult(null);
                    }}
                  >
                    <option value="">none (current definitions)</option>
                    {Object.entries(m.drift_examples).map(([k, v]) => (
                      <option key={k} value={k}>{k.replaceAll("_", " ")}: {v}</option>
                    ))}
                  </select>
                </label>
                <button className="btn btn-primary" onClick={() => inspect()} disabled={busy}>
                  {busy ? "Inspecting…" : "Inspect MCP sandbox"}
                </button>
              </p>
              {error && <p role="alert" className="state state-error" style={{ marginTop: 10 }}>{error}</p>}
              {result && (
                <div className="stack" style={{ marginTop: 14 }} aria-label="Inspection result" role="status">
                  <p className="row">
                    <span className={`chip ${result.activate ? "chip-allowed" : "chip-failed"}`}>
                      {result.activate ? "allowed under this approval" : "activation refused"}
                    </span>
                    <span>{result.status}</span>
                  </p>
                  <p className="faint">
                    Source: {result.source}. Observed digest <span className="hash">{result.observed_digest.slice(0, 20)}…</span>
                  </p>
                  {result.changes.length > 0 && (
                    <ul style={{ margin: 0, paddingLeft: 0, listStyle: "none" }}>
                      {result.changes.map((c, i) => <Change key={i} c={c} />)}
                    </ul>
                  )}
                  {!result.activate && (
                    <p>
                      <button className="btn btn-amber" onClick={() => inspect(result.observed_digest)} disabled={busy}>
                        Approve this exact manifest
                      </button>
                      <span className="faint"> {result.note}</span>
                    </p>
                  )}
                </div>
              )}
            </section>
          </div>
        )}
      </Load>
    </>
  );
}
