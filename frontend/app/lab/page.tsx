"use client";

import { ParetoChart } from "@/components/ParetoChart";
import { Load } from "@/components/States";
import { api } from "@/lib/api";
import type { ArmRow, Evolution, PolicyScore, Rate, StrategyRow } from "@/lib/types";
import { useApi } from "@/lib/useApi";

const frac = (r: Rate) => (r.value === null ? "n/a" : `${r.numerator}/${r.denominator}`);

function Verdict({ s }: { s: StrategyRow }) {
  if (!s.feasible) return <span className="chip chip-failed" title={s.rejection}>rejected</span>;
  if (s.selected) return <span className="chip chip-denied">suggested</span>;
  return s.on_frontier ? <span className="chip chip-verified">non-dominated</span> : <span className="chip chip-neutral">dominated</span>;
}

function Cells({ s }: { s: PolicyScore }) {
  return (
    <>
      <td className="mono">{frac(s.forbidden_effects_prevented)}</td>
      <td className="mono">{frac(s.transfer_prevented)}</td>
      <td className="mono">{frac(s.task_completion)}</td>
      <td className="mono">{frac(s.false_positive_calls)}</td>
    </>
  );
}

function Strategies({ e }: { e: Evolution }) {
  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">Policy strategies on development and held-out scenarios</caption>
        <thead>
          <tr>
            <th rowSpan={2}>Strategy</th>
            <th colSpan={4}>Development ({e.corpus.development.scenarios})</th>
            <th colSpan={4}>Held-out ({e.corpus.held_out.scenarios}); per-task rows are not generalisation tests</th>
            <th rowSpan={2}>Complexity</th>
            <th rowSpan={2}>Verdict</th>
          </tr>
          <tr>
            {[0, 1].flatMap((i) => ["stopped", "sibling", "tasks", "legit denied"].map((h) => <th key={`${i}-${h}`}>{h}</th>))}
          </tr>
        </thead>
        <tbody>
          {e.strategies.map((s) => (
            <tr key={s.name} className={s.selected ? "row-chosen" : undefined}>
              <td>
                <code>{s.name}</code>
                <div className="faint">{s.scope}; sees {s.inputs}</div>
                <span className={`chip ${s.generalisation_test ? "chip-verified" : "chip-neutral"}`} title={s.held_out_basis}>
                  {s.generalisation_test ? "held-out is a generalisation test" : "held-out: compiled from each plan"}
                </span>
                {s.held_out_leaks.length > 0 && s.feasible && (
                  <div className="faint" style={{ color: "#ffb3b3" }}>let through on held-out: {s.held_out_leaks.join(", ")}</div>
                )}
              </td>
              <Cells s={s.development} />
              <Cells s={s.held_out} />
              <td className="mono">{s.development.complexity_mean}</td>
              <td>
                <Verdict s={s} />
                {!s.feasible && <div className="faint">{s.rejection}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Arms({ title, arms }: { title: string; arms: ArmRow[] }) {
  return (
    <div className="table-wrap">
      <table>
        <caption style={{ textAlign: "left", padding: "0 0 8px" }}><strong>{title}</strong></caption>
        <thead>
          <tr><th>Arm</th><th>Attacks stopped</th><th>Tasks completed</th><th>Legit calls denied</th><th>Controls blocked</th><th>Denial rate</th><th>ms</th><th>Cost</th></tr>
        </thead>
        <tbody>
          {arms.map((a) => (
            <tr key={a.arm}>
              <td>{a.arm}<div className="faint">{a.policy}</div>{a.basis && <div className="faint">{a.basis}</div>}</td>
              <td className="mono">{frac(a.score.forbidden_effects_prevented)}</td>
              <td className="mono">{frac(a.score.task_completion)}</td>
              <td className="mono">{frac(a.score.false_positive_calls)}</td>
              <td className="mono">{frac(a.score.control_false_positives)}</td>
              <td className="mono">{frac(a.score.denial_rate)}</td>
              <td className="mono">{a.score.median_ms}</td>
              <td className="mono">{a.score.cost_usd === null ? "n/a" : a.score.cost_usd}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function LabPage() {
  const [evolution, reload] = useApi((s) => api.evolution(3, s), []);
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Policy Lab</h1>
          <p>
            Eight policy strategies are scored on a development set, and one is suggested from those scores alone. Held-out scenarios
            are then scored without influencing that choice. Deterministic fixture results; a language model is not involved.
          </p>
        </div>
        <a className="btn" href={api.evolutionUrl} download="necroshield-evolution.json">Download results (JSON)</a>
      </header>
      <Load value={evolution} onRetry={reload}>
        {(e) => (
          <div className="stack">
            <section className="panel">
              <h2 style={{ marginBottom: 8 }}>Corpus</h2>
              <p>
                {e.corpus.scenarios} scenarios: {e.corpus.attack_scenarios} attacks in {e.corpus.attack_classes} classes and{" "}
                {e.corpus.control_scenarios} benign controls. Development {e.corpus.development.attacks} attacks +{" "}
                {e.corpus.development.controls} controls; held-out {e.corpus.held_out.attacks} + {e.corpus.held_out.controls}.
                Seeded variants (up to {e.corpus.variants_per_attack} per attack; {e.corpus.attacks_without_variants.length} attacks have
                none because no attacker value applies) are reported separately in the JSON.
              </p>
              <p className="faint" style={{ marginTop: 6 }}>{e.corpus.note}</p>
            </section>

            {e.selected && e.selected_held_out_leaks.length > 0 && (
              <section className="panel" style={{ borderLeft: "3px solid var(--amber)" }} role="status" aria-label="Held-out finding">
                <h2 style={{ marginBottom: 6 }}>Held-out finding</h2>
                <p>
                  <code>{e.selected}</code> was suggested from development scores alone. On held-out scenarios it let through{" "}
                  <strong>{e.selected_held_out_leaks.join(", ")}</strong>: it leaves free-text arguments open, and that attack writes
                  an approved key with a bad value. The suggestion is a starting point for a human, not a proven optimum.
                </p>
              </section>
            )}

            <section className="panel">
              <h2 style={{ marginBottom: 10 }}>Complexity against task completion (development)</h2>
              <ParetoChart
                caption="Policy strategies by complexity and task completion; prevention is a constraint, not an axis"
                points={e.strategies.map((s) => ({
                  name: s.name,
                  x: s.development.complexity_mean ?? 0,
                  y: s.development.task_completion.value ?? 0,
                  feasible: s.feasible,
                  frontier: s.on_frontier,
                  selected: s.selected,
                }))}
              />
            </section>

            <section className="panel">
              <h2 style={{ marginBottom: 6 }}>Strategies</h2>
              <p className="faint" style={{ marginBottom: 10 }}>
                <strong>stopped</strong>: attack scenarios with no forbidden effect. <strong>sibling</strong>: ordered (source, target) pairs of attacks on
                the same task, where a policy synthesized for the source is applied to the target. It is true by construction for
                policies that depend only on the plan, so it informs only <code>violation_patch</code> and the global policies. <strong>legit denied</strong>: calls the trusted task needs that were refused. Objectives: {e.objectives}.
              </p>
              <Strategies e={e} />
              <p className="faint" style={{ marginTop: 10 }}>{e.selection_rule}</p>
            </section>

            <section className="panel">
              <h2 style={{ marginBottom: 10 }}>Four arms</h2>
              <div className="stack">
                <Arms title="Development scenarios" arms={e.arms.development} />
                <Arms title="Held-out scenarios" arms={e.arms.held_out} />
              </div>
            </section>

            <section className="panel">
              <h2 style={{ marginBottom: 8 }}>Read this before quoting a number</h2>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {e.caveats.map((c) => <li key={c}>{c}</li>)}
              </ul>
            </section>
          </div>
        )}
      </Load>
    </>
  );
}
