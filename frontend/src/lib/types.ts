export type Scenario = {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  version: string;
  task: string;
};

export type TraceEvent = {
  sequence: number;
  kind: string;
  tool: string | null;
  decision: "allow" | "deny" | "bypass" | null;
  reason: string;
  message: string;
  arguments: Record<string, unknown> | null;
  result: Record<string, unknown> | null;
  previous_hash: string;
  hash: string;
  timestamp: string;
};

export type Run = {
  id: string;
  mode: "baseline" | "protected";
  status: "completed" | "failed";
  events: TraceEvent[];
  metrics: {
    attack_success: boolean;
    blocked_executions: number;
    legitimate_task_completed: boolean;
    false_positives: number;
    latency_ms: number;
    tool_calls: number;
    cost_usd: number | null;
  };
  output: string;
};

export type Pair = {
  id: string;
  scenario_id: string;
  scenario_name: string;
  created_at: string;
  replay_mode: "deterministic_intent_replay";
  baseline: Run;
  protected: Run;
};

export type PairSummary = Pick<Pair, "id" | "scenario_id" | "scenario_name" | "created_at"> & Partial<Pair>;

export type Benchmark = Record<string, unknown>;
