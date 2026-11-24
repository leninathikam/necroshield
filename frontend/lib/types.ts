export type Mode = "baseline" | "protected";

export interface Grant {
  grant_id: string;
  tool: string;
  allowed_args: Record<string, string[] | null>;
}

export interface PolicyDoc {
  version: string;
  grants: Grant[];
}

export interface Check {
  kind: string;
  params: Record<string, string>;
  description: string;
}

export interface ToolCallDoc {
  tool: string;
  args: Record<string, string>;
}

export interface Material {
  resource: string;
  text: string;
  injected_lines: string[];
}

export interface ScenarioView {
  id: string;
  version: string;
  kind: "attack" | "control";
  title: string;
  attack_class: string;
  trusted_task: string;
  attacker_surface: string;
  forbidden_behavior: string;
  digest: string;
  policy: PolicyDoc & { digest: string };
  allowed_tools: string[];
  attack_checks: Check[];
  task_checks: Check[];
  materials: Material[];
  memory: Record<string, string>;
  planned_intents: ToolCallDoc[];
}

export interface ToolCallData {
  intent_index: number;
  tool: string;
  args: Record<string, string>;
  bound_args: Record<string, string>;
  allowed: boolean;
  reason: string;
  grant_id: string | null;
  dispatched: boolean;
  output: string | null;
  error: string | null;
}

export interface Outcome {
  attack_succeeded: boolean;
  task_completed: boolean;
  observed_effects: string[];
}

export interface ChainEvent {
  run_id: string;
  seq: number;
  kind: "run_started" | "tool_call" | "run_completed";
  data: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface RunExport {
  run_id: string;
  mode: Mode;
  outcome: Outcome;
  head: string;
  events: ChainEvent[];
}

export interface PairExport {
  format: string;
  pair_id: string;
  replay_mode: string;
  scenario: { id: string; version: string; kind: string; digest: string; attack_checks: Check[]; task_checks: Check[] };
  policy: PolicyDoc & { digest: string; source: "scenario_default" | "custom" };
  intents: ToolCallDoc[];
  runs: RunExport[];
}

export interface RunSummary {
  pair_id: string;
  created_at: string;
  verified: boolean;
  scenario_id: string;
  scenario_kind: string;
  policy_source: string;
  duration_ms: number;
  baseline: Outcome | null;
  protected: Outcome | null;
  denied_calls: number | null;
}

export interface Attribution {
  intent_index: number;
  tool: string;
  reason: string;
  attack_if_allowed: boolean;
  task_if_allowed: boolean;
  decisive: boolean;
}

export interface RunDetail {
  summary: RunSummary;
  verification: { verified: boolean; problems: string[] };
  analysis: Attribution[];
  export: PairExport;
}

export interface Rate {
  numerator: number;
  denominator: number;
  value: number | null;
}

export interface BenchmarkSummary {
  scenarios: number;
  attack_scenarios: number;
  control_scenarios: number;
  attack_success: Record<Mode, Rate>;
  task_completion: Record<Mode, Rate>;
  false_positives: Rate;
  denial_rate: Rate;
  evaluation_cost_usd: number | null;
  cost_note: string;
}

export interface Benchmark {
  summary: BenchmarkSummary | null;
  rows: RunSummary[];
  unverified_excluded: string[];
  mean_pair_latency_ms: number | null;
  latency_note: string;
  missing_scenarios: string[];
}

export interface McpReplay {
  transport: string;
  evidence: string;
  mode: Mode;
  scenario_id: string;
  tools_listed: string[];
  transcript: {
    tool: string;
    args: Record<string, string>;
    is_error: boolean;
    response: string;
    allowed: boolean | null;
    reason: string;
    dispatched: boolean;
  }[];
  outcome: Outcome;
}

export interface ToolSpecView {
  name: string;
  description: string;
  required: string[];
  optional: string[];
}

export interface LiveRun {
  run_id: string;
  provider: { provider: string; model: string; pricing_configured: boolean };
  temperature: number;
  usage: { prompt_tokens: number; completion_tokens: number };
  cost_usd: number | null;
  latency_ms: number;
  outcome: Outcome & { failure: string | null };
  events: { seq: number; kind: string; data: Record<string, unknown> }[];
  verification: string[];
}

export interface LiveResult {
  evaluation_mode: string;
  repetitions: number;
  runs: LiveRun[];
  note: string;
}

export interface LiveStatus {
  available: boolean;
  reason?: string;
  provider?: string;
  model?: string;
}

export interface Verification {
  verified: boolean;
  problems: string[];
}
