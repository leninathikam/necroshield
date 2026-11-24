import type { Attribution, PairExport, RunExport } from "@/lib/types";
import { argsText, toolCalls } from "@/lib/events";
import { CallChip, OutcomeChips } from "./Chips";

function Column({ run, other }: { run: RunExport; other: RunExport }) {
  const calls = toolCalls(run);
  const otherCalls = toolCalls(other);
  return (
    <section className={`panel is-${run.mode}`} aria-label={`${run.mode} run`}>
      <div className="panel-title">
        <h2 style={{ textTransform: "capitalize" }}>{run.mode}</h2>
        <OutcomeChips outcome={run.outcome} />
      </div>
      <div>
        {calls.map((call) => {
          const changed = otherCalls[call.intent_index]?.allowed !== call.allowed;
          return (
            <div key={call.intent_index} className={`callrow${changed ? " changed" : ""}`}>
              <div>
                <code>{call.tool}</code> <span className="faint">{argsText(call.bound_args)}</span>
                <div className="faint">{call.reason}</div>
              </div>
              <CallChip call={call} />
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 12 }}>
        <div className="label">Observed effects</div>
        <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
          {run.outcome.observed_effects.length === 0 && <li className="dim">none</li>}
          {run.outcome.observed_effects.map((effect) => (
            <li key={effect} style={{ color: effect.startsWith("attack") ? "#ffb3b3" : undefined }}>
              {effect}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

export function RunCompare({ pair }: { pair: PairExport }) {
  const baseline = pair.runs.find((r) => r.mode === "baseline")!;
  const protectedRun = pair.runs.find((r) => r.mode === "protected")!;
  return (
    <div className="compare">
      <Column run={baseline} other={protectedRun} />
      <Column run={protectedRun} other={baseline} />
    </div>
  );
}

export function Attributions({ analysis }: { analysis: Attribution[] }) {
  if (analysis.length === 0) {
    return <p className="dim">The protected run denied nothing, so no decision changed the outcome.</p>;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Intent</th>
            <th>Denied call</th>
            <th>If this one denial were lifted</th>
            <th>Decisive</th>
          </tr>
        </thead>
        <tbody>
          {analysis.map((a) => (
            <tr key={a.intent_index}>
              <td className="mono">#{a.intent_index}</td>
              <td>
                <code>{a.tool}</code>
                <div className="faint">{a.reason}</div>
              </td>
              <td>
                attack {a.attack_if_allowed ? "would succeed" : "still blocked"}, task{" "}
                {a.task_if_allowed ? "completes" : "fails"}
              </td>
              <td>{a.decisive ? <span className="chip chip-denied">decisive</span> : <span className="chip">no change</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
