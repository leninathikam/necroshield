"use client";

import Link from "next/link";
import { useState } from "react";
import { OutcomeChips, VerifiedChip } from "@/components/Chips";
import { Empty, Load } from "@/components/States";
import { api } from "@/lib/api";
import { percent } from "@/lib/events";
import type { Rate } from "@/lib/types";
import { useApi } from "@/lib/useApi";

function RateCell({ rate }: { rate: Rate }) {
  return (
    <>
      <span className="stat-value" style={{ fontSize: 22 }}>{percent(rate.value)}</span>
      <span className="stat-sub">{rate.numerator} / {rate.denominator}</span>
    </>
  );
}

export default function BenchmarkPage() {
  const [bench, reload] = useApi((s) => api.benchmark(s), []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function runAll() {
    setBusy(true);
    setError("");
    try {
      await api.runBenchmark();
      reload();
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
          <h1>Benchmark Studio</h1>
          <p>
            Metrics from the latest verified default-policy run of each scenario. Runs that fail verification are excluded and
            listed. Results are deterministic_intent_replay; live model results are a separate track.
          </p>
        </div>
        <div className="row">
          <button className="btn btn-primary" onClick={runAll} disabled={busy}>{busy ? "Running all scenarios…" : "Run benchmark"}</button>
          <a className="btn" href={api.bundleUrl} download>Download bundle</a>
        </div>
      </header>
      {error && <p role="alert" className="state state-error">Benchmark failed: {error}</p>}
      <Load value={bench} onRetry={reload}>
        {(b) =>
          !b.summary ? (
            <Empty>No verified runs yet. Press Run benchmark to execute every scenario.</Empty>
          ) : (
            <div className="stack">
              <div className="grid-3">
                <div className="panel stat"><span className="label">Attack success, baseline</span><RateCell rate={b.summary.attack_success.baseline} /><span className="stat-sub">over attack scenarios</span></div>
                <div className="panel stat"><span className="label">Attack success, protected</span><RateCell rate={b.summary.attack_success.protected} /><span className="stat-sub">over attack scenarios</span></div>
                <div className="panel stat"><span className="label">Task completion, protected</span><RateCell rate={b.summary.task_completion.protected} /><span className="stat-sub">baseline {percent(b.summary.task_completion.baseline.value)} · over all scenarios</span></div>
                <div className="panel stat"><span className="label">False positives</span><RateCell rate={b.summary.false_positives} /><span className="stat-sub">control scenarios with any denial</span></div>
                <div className="panel stat"><span className="label">Denial rate</span><RateCell rate={b.summary.denial_rate} /><span className="stat-sub">denied / protected calls</span></div>
                <div className="panel stat">
                  <span className="label">Latency · cost</span>
                  <span className="stat-value" style={{ fontSize: 22 }}>{b.mean_pair_latency_ms ?? "n/a"} ms</span>
                  <span className="stat-sub">cost: {b.summary.evaluation_cost_usd === null ? "null" : `$${b.summary.evaluation_cost_usd}`} ({b.summary.cost_note})</span>
                </div>
              </div>
              <p className="faint">{b.latency_note}.</p>
              {b.missing_scenarios.length > 0 && <p className="faint">Not yet run: {b.missing_scenarios.join(", ")}</p>}
              {b.unverified_excluded.length > 0 && <p className="state state-error">Excluded (failed verification): {b.unverified_excluded.join(", ")}</p>}
              <section className="panel">
                <h2 style={{ marginBottom: 10 }}>Per scenario</h2>
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Scenario</th><th>Class</th><th>Baseline</th><th>Protected</th><th>Denied</th><th>Evidence</th><th>Run</th></tr></thead>
                    <tbody>
                      {b.rows.map((r) => (
                        <tr key={r.pair_id}>
                          <td>{r.scenario_id}</td>
                          <td>{r.scenario_kind}</td>
                          <td><OutcomeChips outcome={r.baseline} /></td>
                          <td><OutcomeChips outcome={r.protected} /></td>
                          <td className="mono">{r.denied_calls ?? "n/a"}</td>
                          <td><VerifiedChip verified={r.verified} /></td>
                          <td style={{ whiteSpace: "nowrap" }}><Link href={`/replay/?pair=${r.pair_id}`}>open pair</Link></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          )
        }
      </Load>
    </>
  );
}
