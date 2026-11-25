"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { CallChip, OutcomeChips, VerifiedChip } from "@/components/Chips";
import { ParetoChart } from "@/components/ParetoChart";
import { Attributions } from "@/components/RunCompare";
import { ErrorState, Load } from "@/components/States";
import { api } from "@/lib/api";
import { argsText, toolCalls } from "@/lib/events";
import type { Candidate, Rate, RunDetail, SecurityPatch, Theatre } from "@/lib/types";
import { useApi } from "@/lib/useApi";

const STAGES = ["Attack", "Red team", "Blue team", "Evaluate", "Approve and verify"] as const;
const frac = (r: Rate) => (r.value === null ? "n/a" : `${r.numerator}/${r.denominator}`);

function CandidateTable({ candidates, chosen, onChoose }: { candidates: Candidate[]; chosen: string; onChoose: (n: string) => void }) {
  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">Candidate policies, scored by the independent evaluator</caption>
        <thead>
          <tr>
            <th>Candidate</th>
            <th>Sees</th>
            <th>Attacks stopped</th>
            <th>Sibling attacks stopped</th>
            <th>Tasks completed</th>
            <th>Legit calls denied</th>
            <th>Complexity</th>
          </tr>
        </thead>
        <tbody>
          {candidates.map((c) => (
            <tr key={c.name} className={c.name === chosen ? "row-chosen" : undefined}>
              <td>
                <label className="radio-row">
                  <input type="radio" name="candidate" checked={c.name === chosen} onChange={() => onChoose(c.name)} />
                  <code>{c.name}</code>
                </label>
                {!c.feasible ? (
                  <span className="chip chip-failed" title={c.rejection}>rejected</span>
                ) : c.selected ? (
                  <span className="chip chip-denied">suggested</span>
                ) : c.on_frontier ? (
                  <span className="chip chip-verified">non-dominated</span>
                ) : (
                  <span className="chip chip-neutral">dominated</span>
                )}
                {!c.feasible && <div className="faint" style={{ color: "#ffb3b3" }}>{c.rejection}</div>}
                <div className="faint" style={{ minWidth: 190 }}>{c.description}</div>
              </td>
              <td className="faint">{c.inputs}</td>
              <td className="mono">{frac(c.score.forbidden_effects_prevented)}</td>
              <td className="mono">{frac(c.score.transfer_prevented)}</td>
              <td className="mono">{frac(c.score.task_completion)}</td>
              <td className="mono">{frac(c.score.false_positive_calls)}</td>
              <td className="mono">{c.score.complexity_mean}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Outcome({ result }: { result: RunDetail }) {
  const protectedRun = result.export.runs.find((r) => r.mode === "protected");
  const denied = protectedRun ? toolCalls(protectedRun).filter((c) => !c.allowed) : [];
  return (
    <div className="stack" role="status">
      <div className="compare">
        {result.export.runs.map((run) => (
          <section key={run.run_id} className={`panel is-${run.mode}`} aria-label={`${run.mode} outcome`}>
            <div className="panel-title">
              <h3 style={{ textTransform: "capitalize" }}>{run.mode}</h3>
              <OutcomeChips outcome={run.outcome} />
            </div>
            {run.mode === "protected" &&
              denied.map((c) => (
                <div key={c.intent_index} className="callrow">
                  <div>
                    <code>{c.tool}</code> <span className="faint">{argsText(c.bound_args)}</span>
                    <div className="faint">{c.reason}</div>
                  </div>
                  <CallChip call={c} />
                </div>
              ))}
            {run.mode === "protected" && denied.length === 0 && <p className="dim">No call was denied.</p>}
          </section>
        ))}
      </div>
      <p className="row">
        <VerifiedChip verified={result.verification.verified} />
        <span className="faint">policy source: {result.export.policy.source} · {result.export.policy.version}</span>
      </p>
      <p className="row">
        <Link className="btn" href={`/replay/?pair=${result.summary.pair_id}`}>Replay Lab</Link>
        <Link className="btn" href={`/graph/?pair=${result.summary.pair_id}`}>Execution graph</Link>
        <Link className="btn" href={`/evidence/?pair=${result.summary.pair_id}`}>Evidence</Link>
      </p>
    </div>
  );
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

function PatchPanel({ data }: { data: Theatre }) {
  const options = [
    ...data.scenario.peer_attacks.map((peer) => ({ value: `violation_patch|${peer}`, label: `violation_patch that was built for ${peer}` })),
    { value: "tool_allowlist|", label: "tool_allowlist (tools only, no argument limits)" },
    { value: "allow_all|", label: "allow_all (no restriction)" },
  ];
  const [choice, setChoice] = useState(options[0]?.value ?? "tool_allowlist|");
  const [patch, setPatch] = useState<SecurityPatch | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function compile() {
    setBusy(true);
    setError("");
    setPatch(null);
    const [base, from] = choice.split("|");
    try {
      setPatch(await api.patch(data.scenario.id, base ?? "tool_allowlist", from || undefined));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel stage" aria-labelledby="s6">
      <h2 id="s6">Security patch</h2>
      <p className="dim">
        Pick the policy that was deployed when the attack got through. The compiler reproduces the failure, proposes a fix as
        structured operations, and re-runs a regression specification on development and held-out scenarios. It applies nothing.
      </p>
      <p className="row" style={{ marginTop: 10, alignItems: "flex-end" }}>
        <label>
          Deployed policy
          <select aria-label="Deployed policy" value={choice} onChange={(e) => setChoice(e.target.value)}>
            {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        <button className="btn" onClick={compile} disabled={busy}>{busy ? "Compiling…" : "Compile security patch"}</button>
      </p>
      {error && <p role="alert" className="state state-error" style={{ marginTop: 10 }}>{error}</p>}
      {patch && (
        <div className="stack" style={{ marginTop: 14 }} aria-label="Compiled patch">
          <ul style={{ margin: 0, paddingLeft: 18 }}>{patch.explanation.map((line) => <li key={line}>{line}</li>)}</ul>
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Regression results</caption>
              <thead><tr><th>Case</th><th>Split</th><th>Result</th></tr></thead>
              <tbody>
                {patch.results.map((r) => (
                  <tr key={r.id}>
                    <td><code>{r.id}</code></td>
                    <td>{r.split === "development" ? "development" : "held-out"}</td>
                    <td>{r.passed ? <span className="chip chip-allowed">pass</span> : <span className="chip chip-failed">fail: {r.problems.join("; ")}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="faint">
            Status: {patch.activation.status}; applied: {String(patch.activation.applied)}; requires {patch.activation.requires}. Patch{" "}
            <code>{patch.patch_id}</code>.
          </p>
          <p className="row">
            <button className="btn" onClick={() => download(`necroshield-patch-${patch.patch_id}.json`, JSON.stringify(patch, null, 2), "application/json")}>Download patch (JSON)</button>
            <button className="btn" onClick={() => download(`necroshield-patch-${patch.patch_id}.md`, patch.report_markdown, "text/markdown")}>Download report (Markdown)</button>
          </p>
        </div>
      )}
    </section>
  );
}

export default function TheatrePage() {
  const [corpus, reloadCorpus] = useApi((s) => api.corpus(s), []);
  const [scenarioId, setScenarioId] = useState("tool_response_injection");
  const [data, setData] = useState<Theatre | null>(null);
  const [revealed, setRevealed] = useState(0);
  const [chosen, setChosen] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<RunDetail | null>(null);
  const [approving, setApproving] = useState(false);
  const generation = useRef(0);
  const approveGeneration = useRef(0);

  async function run() {
    const mine = ++generation.current;
    approveGeneration.current++;  // an approval started for an earlier run must not render under this one
    setRunning(true);
    setError("");
    setResult(null);
    setData(null);
    setRevealed(0);
    try {
      const t = await api.theatre(scenarioId);
      if (mine !== generation.current) return;
      setData(t);
      setChosen(t.selected ?? t.candidates[0]?.name ?? "");
      setRevealed(window.matchMedia("(prefers-reduced-motion: reduce)").matches ? STAGES.length : 1);
    } catch (e) {
      if (mine === generation.current) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (mine === generation.current) setRunning(false);
    }
  }

  useEffect(() => {
    if (!data || revealed === 0 || revealed >= STAGES.length) return;
    const timer = window.setTimeout(() => setRevealed((n) => n + 1), 900);
    return () => window.clearTimeout(timer);
  }, [data, revealed]);

  async function approve() {
    if (!data) return;
    const mine = ++approveGeneration.current;
    setApproving(true);
    setError("");
    try {
      const outcome = await api.approve(data.scenario.id, chosen);
      if (mine !== approveGeneration.current) return;
      setResult(outcome);
      setRevealed(STAGES.length);
    } catch (e) {
      if (mine === approveGeneration.current) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (mine === approveGeneration.current) setApproving(false);
    }
  }

  const shown = (n: number) => revealed >= n;
  const points =
    data?.candidates.map((c) => ({
      name: c.name,
      x: c.score.complexity_mean ?? 0,
      y: c.score.task_completion.value ?? 0,
      feasible: c.feasible,
      frontier: c.on_frontier,
      selected: c.selected,
    })) ?? [];

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Attack Theatre</h1>
          <p>
            An attack compromises an unprotected agent. A Blue Team proposes defenses, an independent evaluator tests each one, and
            you approve or reject. Every step below is a real run on this server; nothing is activated until you approve it.
          </p>
        </div>
      </header>

      <Load value={corpus} onRetry={reloadCorpus}>
        {(rows) => (
          <section className="panel row" style={{ alignItems: "flex-end" }} aria-label="Choose an attack">
            <label>
              Attack scenario
              <select aria-label="Attack scenario" value={scenarioId} onChange={(e) => setScenarioId(e.target.value)}>
                {rows
                  .filter((r) => r.kind === "attack")
                  .map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.title} ({r.split === "development" ? "development" : "held-out"})
                    </option>
                  ))}
              </select>
            </label>
            <button className="btn btn-primary" onClick={run} disabled={running}>
              {running ? "Running…" : "Run Attack Theatre"}
            </button>
          </section>
        )}
      </Load>

      <ol className="rail" aria-label="Stages">
        {STAGES.map((name, i) => (
          <li key={name} aria-current={revealed === i + 1 ? "step" : undefined} className={revealed > i ? "reached" : ""}>
            <span className="rail-n">{i + 1}</span> {name}
          </li>
        ))}
      </ol>
      <p className="sr-only" aria-live="polite">{revealed > 0 && revealed <= STAGES.length ? `Stage ${Math.min(revealed, STAGES.length)}: ${STAGES[Math.min(revealed, STAGES.length) - 1]}` : ""}</p>

      {error && <ErrorState prefix="Failed" message={error} />}
      {!data && !running && !error && (
        <div className="state">Choose an attack and press <strong>Run Attack Theatre</strong>. The stages reveal over a few seconds.</div>
      )}

      {data && (
        <div className="stack">
          {shown(1) && (
            <section className="panel stage stage-attack" aria-labelledby="s1">
              <h2 id="s1">1 · Attack: {data.scenario.title}</h2>
              <p className="dim">{data.scenario.attacker_surface}</p>
              <p style={{ marginTop: 8 }}>
                Trusted task: <em>{data.scenario.trusted_task}</em>
              </p>
              <div className="label" style={{ marginTop: 12 }}>Unprotected run: observed effects</div>
              <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                {data.red_team.observed_effects.map((e) => (
                  <li key={e} style={{ color: e.startsWith("attack") ? "#ffb3b3" : undefined }}>{e}</li>
                ))}
              </ul>
              <div className="label" style={{ marginTop: 12 }}>Calls the agent made that its task never asked for</div>
              {data.red_team.violating_calls.map((c, i) => (
                <div key={i} className="callrow"><div><code>{c.tool}</code> <span className="faint">{argsText(c.args)}</span></div><span className="chip chip-attack">attacker-driven</span></div>
              ))}
            </section>
          )}

          {shown(2) && (
            <section className="panel stage" aria-labelledby="s2">
              <h2 id="s2">2 · Red team: seeded variations</h2>
              <p className="dim">
                Only attacker-chosen values change ({data.red_team.axis}); the same seed always gives the same variants. They are
                robustness checks, not new attack classes.
              </p>
              <p className="row" style={{ marginTop: 8 }}>
                {data.red_team.seeded_variants.map((v) => <code key={v} className="chip chip-neutral">{v}</code>)}
                {data.scenario.peer_attacks.length > 0 && (
                  <span className="faint">Sibling attacks on the same task: {data.scenario.peer_attacks.join(", ")}</span>
                )}
              </p>
            </section>
          )}

          {shown(3) && (
            <section className="panel stage" aria-labelledby="s3">
              <h2 id="s3">3 · Blue team: candidate policies</h2>
              <p className="dim" style={{ marginBottom: 10 }}>
                Structured capability grants built from the trusted task. The model never edits the enforcement engine and cannot
                grant itself anything.
              </p>
              <CandidateTable candidates={data.candidates} chosen={chosen} onChoose={setChosen} />
            </section>
          )}

          {shown(4) && (
            <section className="panel stage" aria-labelledby="s4">
              <h2 id="s4">4 · Independent evaluation</h2>
              <p className="dim" style={{ marginBottom: 10 }}>
                Mandatory constraint: no forbidden effect on the scenario or its variants. Candidates that fail it are rejected,
                however convenient they are. Objectives: {data.objectives}.
              </p>
              <div className="grid-2">
                <ParetoChart points={points} caption="Candidate policies by complexity and task completion; rejected candidates are crosses" />
                <div>
                  <div className="label">Which decision changed the result (selected candidate)</div>
                  <Attributions analysis={data.counterfactual} />
                  <p className="faint" style={{ marginTop: 10 }}>{data.selection_rule}</p>
                </div>
              </div>
            </section>
          )}

          {shown(5) && <PatchPanel key={data.scenario.id} data={data} />}

          {shown(5) && (
            <section className="panel stage" aria-labelledby="s5">
              <h2 id="s5">5 · Human approval and verification</h2>
              <p className="dim">{data.approval}</p>
              <p className="row" style={{ marginTop: 10 }}>
                <span>Candidate to run: <code>{chosen}</code></span>
                {data.candidates.find((c) => c.name === chosen && !c.feasible) && (
                  <span className="chip chip-failed">this candidate was rejected; running it shows why</span>
                )}
                <button className="btn btn-primary" onClick={approve} disabled={approving}>
                  {approving ? "Running…" : "Approve and run this candidate"}
                </button>
              </p>
              {result && <div style={{ marginTop: 14 }}><Outcome result={result} /></div>}
            </section>
          )}
        </div>
      )}
      {data && <p className="faint" style={{ marginTop: 12 }}>
        {data.evaluation_mode}: identical intended calls against each policy. Fixture results say nothing about how a language
        model behaves.
      </p>}
    </>
  );
}
