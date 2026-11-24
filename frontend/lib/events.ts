import type { ChainEvent, RunExport, ToolCallData } from "./types";

export type CallState = "allowed" | "denied" | "failed";

export function toolCalls(run: RunExport): ToolCallData[] {
  return run.events.filter((e: ChainEvent) => e.kind === "tool_call").map((e) => e.data as unknown as ToolCallData);
}

export function callState(call: ToolCallData): CallState {
  if (!call.allowed) return "denied";
  if (call.error) return "failed";
  return "allowed";
}

export function short(hash: string, n = 10): string {
  return hash.slice(0, n);
}

export function argsText(args: Record<string, string>): string {
  return Object.entries(args)
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(", ");
}

export function percent(value: number | null): string {
  return value === null ? "n/a" : `${Math.round(value * 1000) / 10}%`;
}
