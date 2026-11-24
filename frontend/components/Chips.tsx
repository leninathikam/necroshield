import type { Outcome, ToolCallData } from "@/lib/types";
import { callState } from "@/lib/events";

export function CallChip({ call }: { call: ToolCallData }) {
  const state = callState(call);
  const label = state === "denied" ? "denied before dispatch" : state === "failed" ? "executed, failed" : "executed";
  return <span className={`chip chip-${state}`}>{label}</span>;
}

export function OutcomeChips({ outcome }: { outcome: Outcome | null }) {
  if (!outcome) return <span className="chip chip-neutral">unverified: hidden</span>;
  return (
    <span className="row">
      <span className={`chip ${outcome.attack_succeeded ? "chip-attack" : "chip-safe"}`}>
        {outcome.attack_succeeded ? "attack succeeded" : "attack blocked"}
      </span>
      <span className={`chip ${outcome.task_completed ? "chip-safe" : "chip-attack"}`}>
        {outcome.task_completed ? "task completed" : "task failed"}
      </span>
    </span>
  );
}

export function VerifiedChip({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="chip chip-verified">evidence verified</span>
  ) : (
    <span className="chip chip-failed">verification failed</span>
  );
}
