"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { toolCalls } from "@/lib/events";
import type { RunDetail, ScenarioView, Verification } from "@/lib/types";

type Phase = "idle" | "running" | "done" | "error";
const STEPS = ["Attack", "Compromise", "Activate defense", "Replay", "Verify"] as const;

/** Attack → Compromise → Activate Defense → Replay → Verify, driven by a real run on this server.
 * Each step reveals data from the run's evidence; nothing here is pre-rendered. */
export function HeroSequence({ scenarios }: { scenarios: ScenarioView[] }) {
  const attacks = scenarios.filter((s) => s.kind === "attack");
  const [scenarioId, setScenarioId] = useState(attacks[0]?.id ?? "");
  const [phase, setPhase] = useState<Phase>("idle");
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [check, setCheck] = useState<Verification | null>(null);
  const [step, setStep] = useState(-1);
  const [error, setError] = useState("");
  const scenario = scenarios.find((s) => s.id === (detail?.export.scenario.id ?? scenarioId));

  useEffect(() => {
    if (phase !== "done" || step >= STEPS.length - 1) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const timer = window.setTimeout(() => setStep((s) => (reduced ? STEPS.length - 1 : s + 1)), reduced ? 0 : 900);
    return () => window.clearTimeout(timer);
  }, [phase, step]);

  async function start() {
    setPhase("running");
    setStep(-1);
    setCheck(null);
    setError("");
    try {
      const run = await api.startRun(scenarioId);
      const recheck = await api.verify(run.export);
      setDetail(run);
      setCheck(recheck);
      setPhase("done");
      setStep(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  const baseline = detail?.export.runs.find((r) => r.mode === "baseline");
  const protectedRun = detail?.export.runs.find((r) => r.mode === "protected");
  const denied = protectedRun ? toolCalls(protectedRun).filter((c) => !c.allowed) : [];
  const text: string[] = [
    scenario ? `${scenario.attacker_surface} ${scenario.materials.reduce((n, m) => n + m.injected_lines.length, 0)} injected instruction(s).` : "",
    baseline
      ? baseline.outcome.attack_succeeded
        ? `Baseline: ${baseline.outcome.observed_effects.find((e) => e.startsWith("attack")) ?? "attack effect observed"}.`
        : "Baseline: no attack effect observed."
      : "",
    detail ? `Default-deny policy ${detail.export.policy.version} with ${detail.export.policy.grants.length} grants.` : "",
    protectedRun
      ? `Same ${toolCalls(protectedRun).length} intended calls. Denied before dispatch: ${denied.map((c) => c.tool).join(", ") || "none"}. Task ${protectedRun.outcome.task_completed ? "completed" : "failed"}.`
      : "",
    check
      ? check.verified
        ? "Standalone verifier: chain links, policy decisions, and outcomes re-derived from effects all check out."
        : `Verifier rejected: ${check.problems[0]}`
      : "",
  ];

  return (
    <section className="panel" aria-labelledby="hero-title">
      <div className="panel-title">
        <div>
          <h2 id="hero-title">Attack, compromise, defend, replay, verify</h2>
          <p className="dim" style={{ marginTop: 4 }}>
            Runs a real baseline/protected pair on this server, then checks the evidence with the standalone verifier.
          </p>
        </div>
        <div className="row">
          <label>
            <span className="sr-only">Scenario</span>
            <select value={scenarioId} onChange={(e) => setScenarioId(e.target.value)} aria-label="Scenario for the sequence">
              {attacks.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.title}
                </option>
              ))}
            </select>
          </label>
          <button className="btn btn-primary" onClick={start} disabled={phase === "running" || !scenarioId}>
            {phase === "running" ? "Running…" : "Run the sequence"}
          </button>
        </div>
      </div>
      <ol className="hero" aria-live="polite">
        {STEPS.map((name, i) => (
          <li
            key={name}
            className={`hero-step${i === step ? " active" : ""}${i < step || (i === step && i === STEPS.length - 1) ? " done" : ""}${i === 1 ? " bad" : i >= 3 ? " good" : ""}`}
            style={{ listStyle: "none" }}
          >
            <h3>
              {i + 1}. {name}
            </h3>
            <p>{phase === "done" && i <= step ? text[i] : i === 0 && scenario ? scenario.attacker_surface : ""}</p>
          </li>
        ))}
      </ol>
      {phase === "error" && <p role="alert" className="state-error">Run failed: {error}</p>}
      {detail && step >= STEPS.length - 1 && (
        <p className="row">
          <Link className="btn" href={`/replay/?pair=${detail.summary.pair_id}`}>Open in Replay Lab</Link>
          <Link className="btn" href={`/graph/?pair=${detail.summary.pair_id}`}>Open the graph</Link>
          <Link className="btn" href={`/evidence/?pair=${detail.summary.pair_id}`}>Inspect evidence</Link>
        </p>
      )}
    </section>
  );
}
