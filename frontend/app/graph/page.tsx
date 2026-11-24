"use client";

import { useState } from "react";
import { AttackGraph } from "@/components/AttackGraph";
import { RunPage } from "@/components/RunPage";
import type { Mode } from "@/lib/types";

export default function GraphPage() {
  const [mode, setMode] = useState<Mode>("baseline");
  return (
    <RunPage
      title="Execution Graph"
      intro="The agent, its attacker-controlled input, the policy gateway in front of every tool, each tool, and the effects observed afterwards. Playback follows the run's hash-chained events in order."
    >
      {(d, scenario) => {
        const run = d.export.runs.find((r) => r.mode === mode)!;
        return (
          <section className="panel">
            <div className="panel-title">
              <div className="row" role="group" aria-label="Run to display">
                {(["baseline", "protected"] as const).map((m) => (
                  <button key={m} className="btn" aria-pressed={m === mode} onClick={() => setMode(m)}>
                    {m}
                  </button>
                ))}
              </div>
              <span className="faint">
                violet: executed · amber dashed: denied before dispatch · red: failed or attack effect
              </span>
            </div>
            <AttackGraph
              key={run.run_id}
              run={run}
              checks={{ attack: d.export.scenario.attack_checks, task: d.export.scenario.task_checks }}
              surface={scenario?.attacker_surface ?? d.export.scenario.id}
            />
          </section>
        );
      }}
    </RunPage>
  );
}
