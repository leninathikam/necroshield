"use client";

import Link from "next/link";
import { HeroSequence } from "@/components/HeroSequence";
import { OutcomeChips, VerifiedChip } from "@/components/Chips";
import { Empty, Load } from "@/components/States";
import { api } from "@/lib/api";
import { percent } from "@/lib/events";
import { useApi } from "@/lib/useApi";

export default function Dashboard() {
  const [scenarios, reloadScenarios] = useApi((s) => api.scenarios(s), []);
  const [corpus, reloadCorpus] = useApi((s) => api.corpus(s), []);
  const [runs, reloadRuns] = useApi((s) => api.runs(8, s), []);
  const [bench, reloadBench] = useApi((s) => api.benchmark(s), []);

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p>
            Adversarial tests for agent tool use, on synthetic data only. Pick an attack and follow it from the compromise to a
            generated policy, a test of which denial mattered, your approval, and a check of the evidence. Each run happens
            twice from fresh state, unprotected and behind a default-deny policy.
          </p>
        </div>
      </header>

      <Load value={corpus} onRetry={reloadCorpus}>
        {(rows) => (
          <HeroSequence
            attacks={rows.filter((r) => r.kind === "attack")}
            onRun={() => {
              reloadRuns();
              reloadBench();
            }}
          />
        )}
      </Load>

      <div className="grid-3" style={{ marginTop: 16 }}>
        <Load value={scenarios} onRetry={reloadScenarios}>
          {(list) => (
            <div className="panel stat">
              <span className="label">Scenarios</span>
              <span className="stat-value">{list.length}</span>
              <span className="stat-sub">
                {list.filter((s) => s.kind === "attack").length} attack · {list.filter((s) => s.kind === "control").length} control
              </span>
            </div>
          )}
        </Load>
        <Load value={bench} onRetry={reloadBench}>
          {(b) => (
            <div className="panel stat">
              <span className="label">Baseline attack success</span>
              <span className="stat-value">{b.summary ? percent(b.summary.attack_success.baseline.value) : "n/a"}</span>
              <span className="stat-sub">
                {b.summary
                  ? `${b.summary.attack_success.baseline.numerator}/${b.summary.attack_success.baseline.denominator} attack scenarios run so far (latest verified)`
                  : "Run the benchmark to measure"}
              </span>
            </div>
          )}
        </Load>
        <Load value={bench} onRetry={reloadBench}>
          {(b) => (
            <div className="panel stat">
              <span className="label">Protected attack success</span>
              <span className="stat-value">{b.summary ? percent(b.summary.attack_success.protected.value) : "n/a"}</span>
              <span className="stat-sub">
                {b.summary
                  ? `task completion ${percent(b.summary.task_completion.protected.value)} · false positives ${
                      b.summary.false_positives.denominator === 0
                        ? "n/a (control not run yet)"
                        : `${b.summary.false_positives.numerator}/${b.summary.false_positives.denominator}`
                    }`
                  : "No verified benchmark yet"}
              </span>
            </div>
          )}
        </Load>
      </div>

      <section className="panel" style={{ marginTop: 16 }} aria-labelledby="recent">
        <div className="panel-title">
          <h2 id="recent">Recent activity</h2>
          <button className="btn" onClick={reloadRuns}>
            Refresh
          </button>
        </div>
        <Load value={runs} onRetry={reloadRuns}>
          {(list) =>
            list.length === 0 ? (
              <Empty>No runs stored yet. Run the sequence above or open the Attack Arena.</Empty>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Scenario</th>
                      <th>Policy</th>
                      <th>Baseline</th>
                      <th>Protected</th>
                      <th>Evidence</th>
                      <th>When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((r) => (
                      <tr key={r.pair_id}>
                        <td>
                          <Link href={`/replay/?pair=${r.pair_id}`}>{r.scenario_id}</Link>
                        </td>
                        <td>{r.policy_source === "custom" ? "custom" : "default"}</td>
                        <td><OutcomeChips outcome={r.baseline} /></td>
                        <td><OutcomeChips outcome={r.protected} /></td>
                        <td><VerifiedChip verified={r.verified} /></td>
                        <td className="faint">{new Date(r.created_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
      </section>
    </>
  );
}
