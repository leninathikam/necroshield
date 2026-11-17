import { ArrowRight, Check, CircleSlash, ShieldCheck, ShieldOff } from "lucide-react";
import type { Pair, Run } from "@/lib/types";

function RunCard({ run, title }: { run: Run; title: string }) {
  const protectedRun = run.mode === "protected";
  const Icon = protectedRun ? ShieldCheck : ShieldOff;
  return <article className={`run-card ${run.mode}`}>
    <div className="run-card-title"><span><Icon size={16} />{title}</span><span className="mono muted">{run.status}</span></div>
    <div className="run-outcome"><span className={`outcome ${run.metrics.attack_success ? "compromised" : "contained"}`}>
      {run.metrics.attack_success ? "Attack effect observed" : "No attack effect"}</span><span className="mono muted">{run.metrics.latency_ms.toFixed(2)} ms</span></div>
    <div className="run-facts"><span>{run.metrics.legitimate_task_completed ? <Check size={13} /> : <CircleSlash size={13} />}Legitimate task {run.metrics.legitimate_task_completed ? "completed" : "incomplete"}</span><span>{run.metrics.blocked_executions} denied · {run.metrics.tool_calls} calls executed</span></div>
    <p className="run-output">{run.output}</p>
  </article>;
}

export function Comparison({ pair }: { pair: Pair | null }) {
  if (!pair) return <div className="comparison-empty"><span>01 / UNRESTRICTED FIXTURE</span><ArrowRight size={18} /><span>02 / POLICY ENFORCED</span><p>Two independent sandboxes. One identical intent sequence.</p></div>;
  return <div className="comparison-grid"><RunCard run={pair.baseline} title="Baseline" /><RunCard run={pair.protected} title="Protected" /></div>;
}
