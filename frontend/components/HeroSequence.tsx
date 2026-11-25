"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { CorpusRow, RunDetail, Theatre, Verification } from "@/lib/types";

const STEPS = ["Attack", "Policy generation", "Counterfactual test", "Human approval", "Independent verification"] as const;
const DEFAULT_ATTACK = "tool_response_injection";

type Phase = "idle" | "loading" | "awaiting" | "approving" | "done" | "error";

/** Attack → Policy generation → Counterfactual test → Human approval → Independent verification.
 * Steps 1-3 come from one Attack Theatre call, step 4 waits for a click, and step 5 re-checks the evidence of
 * the approved run. Every line is built from the response; nothing here is pre-rendered. */
export function HeroSequence({ attacks, onRun }: { attacks: CorpusRow[]; onRun?: () => void }) {
  const [attackId, setAttackId] = useState(attacks.some((a) => a.id === DEFAULT_ATTACK) ? DEFAULT_ATTACK : (attacks[0]?.id ?? ""));
  const [phase, setPhase] = useState<Phase>("idle");
  const [data, setData] = useState<Theatre | null>(null);
  const [run, setRun] = useState<RunDetail | null>(null);
  const [check, setCheck] = useState<Verification | null>(null);
  const [step, setStep] = useState(-1);
  const [error, setError] = useState("");

  // Reveal steps 1-3 one at a time once the theatre response has arrived.
  useEffect(() => {
    if (phase !== "awaiting" || step >= 3) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const timer = window.setTimeout(() => setStep((s) => (reduced ? 3 : Math.min(s + 1, 3))), reduced ? 0 : 800);
    return () => window.clearTimeout(timer);
  }, [phase, step]);

  async function start() {
    setPhase("loading");
    setStep(-1);
    setData(null);
    setRun(null);
    setCheck(null);
    setError("");
    try {
      setData(await api.theatre(attackId));
      setPhase("awaiting");
      setStep(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  async function approve() {
    if (!data?.selected) return;
    setPhase("approving");
    setError("");
    try {
      const approved = await api.approve(data.scenario.id, data.selected);
      const recheck = await api.verify(approved.export);
      setRun(approved);
      setCheck(recheck);
      setStep(4);
      setPhase("done");
      onRun?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  const rejected = data?.candidates.filter((c) => !c.feasible) ?? [];
  const decisive = data?.counterfactual.filter((c) => c.decisive) ?? [];
  const protectedRun = run?.export.runs.find((r) => r.mode === "protected");
  const text: string[] = data
    ? [
        `${data.scenario.attacker_surface} Unprotected run: ${
          data.red_team.observed_effects.find((e) => e.startsWith("attack")) ?? "no attack effect observed"
        }.`,
        data.selected
          ? `${data.candidates.length} candidate policies built from the trusted task and tested; ${rejected.length} rejected for letting the forbidden effect through. Suggested: ${data.selected}. ${data.lab_suggestion.statement}`
          : `${data.candidates.length} candidate policies tested; none passed the mandatory constraint.`,
        decisive.length > 0
          ? `Remove the decisive denial and the attack returns: ${decisive.map((d) => `${d.tool} (${d.reason})`).join("; ")}.`
          : "No single denial was decisive for the selected candidate.",
        run
          ? `Approved ${data.selected}. Same intended calls, now behind that policy: attack ${protectedRun?.outcome.attack_succeeded ? "succeeded" : "blocked"}, task ${protectedRun?.outcome.task_completed ? "completed" : "failed"}.`
          : phase === "awaiting" && step >= 3
            ? `Waiting for you. Nothing is activated until you approve ${data.selected ?? "a candidate"}.`
            : "",
        check
          ? check.verified
            ? "This server's copy of the standalone verifier re-derived the hash chain, every policy decision and the outcomes from the recorded effects. For a check that does not trust this server, download the export and run python scripts/verify_evidence.py offline."
            : `Verifier rejected the evidence: ${check.problems[0]}`
          : "",
      ]
    : ["", "", "", "", ""];
  const shown = (i: number) => data !== null && i <= step;

  return (
    <section className="panel" aria-labelledby="hero-title">
      <div className="panel-title">
        <div>
          <h2 id="hero-title">Attack, policy generation, counterfactual test, human approval, independent verification</h2>
          <p className="dim" style={{ marginTop: 4 }}>
            Real calls to this server, fixture agent. You approve before anything runs under the generated policy.
          </p>
        </div>
        <div className="row">
          <label>
            <span className="sr-only">Attack</span>
            <select value={attackId} onChange={(e) => setAttackId(e.target.value)} aria-label="Attack for the sequence">
              {attacks.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.title}
                </option>
              ))}
            </select>
          </label>
          <button className="btn btn-primary" onClick={start} disabled={phase === "loading" || phase === "approving" || !attackId}>
            {phase === "loading" ? "Running…" : "Run the sequence"}
          </button>
        </div>
      </div>
      <ol className="hero" aria-live="polite">
        {STEPS.map((name, i) => (
          <li
            key={name}
            className={`hero-step${i === step ? " active" : ""}${i < step || (i === step && phase === "done") ? " done" : ""}${i === 0 ? " bad" : i >= 2 ? " good" : ""}`}
            style={{ listStyle: "none" }}
          >
            <h3>
              {i + 1}. {name}
            </h3>
            <p>{shown(i) ? text[i] : ""}</p>
            {i === 3 && phase === "awaiting" && step >= 3 && data?.selected && (
              <button className="btn btn-primary" onClick={approve}>
                Approve and run
              </button>
            )}
            {i === 3 && phase === "approving" && <span className="faint">Running…</span>}
          </li>
        ))}
      </ol>
      {phase === "error" && <p role="alert" className="state-error">Run failed: {error}</p>}
      {run && phase === "done" && (
        <p className="row">
          <Link className="btn" href={`/replay/?pair=${run.summary.pair_id}`}>Open in Replay Lab</Link>
          <Link className="btn" href={`/graph/?pair=${run.summary.pair_id}`}>Open the graph</Link>
          <Link className="btn" href={`/evidence/?pair=${run.summary.pair_id}`}>Inspect evidence</Link>
          <Link className="btn" href={`/theatre/`}>Open the full Attack Theatre</Link>
        </p>
      )}
    </section>
  );
}
