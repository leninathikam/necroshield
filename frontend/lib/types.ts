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

export interface LiveStatus {
  available: boolean;
  configured?: boolean;
  reason?: string;
  provider?: string;
  model?: string;
}

export interface Verification {
  verified: boolean;
  problems: string[];
}

export interface CorpusRow {
  id: string;
  version: string;
  kind: "attack" | "control";
  title: string;
  attack_class: string;
  digest: string;
  split: "development" | "held_out";
}

export interface PolicyScore {
  scenarios: number;
  attack_scenarios: number;
  control_scenarios: number;
  forbidden_effects_prevented: Rate;
  task_completion: Rate;
  false_positive_calls: Rate;
  false_positive_scenarios: Rate;
  control_false_positives: Rate;
  denial_rate: Rate;
  complexity_mean: number | null;
  median_ms: number | null;
  cost_usd: number | null;
  transfer_prevented: Rate;
}

export interface StrategyRow {
  name: string;
  scope: "per-scenario" | "global";
  inputs: string;
  description: string;
  feasible: boolean;
  rejection: string;
  on_frontier: boolean;
  selected: boolean;
  development: PolicyScore;
  held_out: PolicyScore;
  variants: { development: PolicyScore; held_out: PolicyScore };
  transfer: { development: Rate; held_out: Rate };
}

export interface ArmRow {
  arm: string;
  policy: string;
  score: PolicyScore;
}

export interface Evolution {
  corpus: {
    scenarios: number;
    attack_scenarios: number;
    control_scenarios: number;
    attack_classes: number;
    development: { scenarios: number; attacks: number; controls: number };
    held_out: { scenarios: number; attacks: number; controls: number };
    variants_per_attack: number;
    note: string;
  };
  evaluation_mode: string;
  objectives: string;
  selection_rule: string;
  selected: string | null;
  strategies: StrategyRow[];
  arms: { development: ArmRow[]; held_out: ArmRow[] };
  caveats: string[];
}

export interface Candidate {
  name: string;
  description: string;
  inputs: string;
  policy: PolicyDoc & { digest: string };
  feasible: boolean;
  rejection: string;
  on_frontier: boolean;
  selected: boolean;
  score: PolicyScore;
  tested_on: { scenario: string; variants: string[] };
}

export interface Theatre {
  scenario: {
    id: string;
    version: string;
    title: string;
    attack_class: string;
    trusted_task: string;
    attacker_surface: string;
    digest: string;
    peer_attacks: string[];
  };
  red_team: {
    seeded_variants: string[];
    axis: string;
    baseline_attack_succeeded: boolean;
    observed_effects: string[];
    violating_calls: ToolCallDoc[];
  };
  candidates: Candidate[];
  selected: string | null;
  selection_rule: string;
  objectives: string;
  counterfactual: Attribution[];
  approval: string;
  evaluation_mode: string;
}

export interface SigningInfo {
  enabled: boolean;
  alg?: string;
  key_id?: string;
  public_key?: string;
  reason?: string;
}

export interface PatchResult {
  id: string;
  split: string;
  passed: boolean;
  problems: string[];
  observed: { attack_succeeded: boolean; task_completed: boolean; legit_denied: number };
}

export interface SecurityPatch {
  patch_id: string;
  scenario: { id: string; version: string; digest: string; split: string };
  failure: { base_strategy: string; base_from: string; observed_effects: string[]; calls_let_through: ToolCallDoc[] };
  proposed: { strategy: string; policy: PolicyDoc & { digest: string } };
  operations: { op: string; tool: string; explain: string }[];
  results: PatchResult[];
  all_cases_pass: boolean;
  aggregate: Record<"development" | "held_out", { before: PolicyScore; after: PolicyScore; scenarios_using_patch: number }>;
  activation: { status: string; applied: boolean; requires: string };
  explanation: string[];
  report_markdown: string;
}

export interface ManifestTool {
  name: string;
  description: string;
  hash: string;
  input: { properties: Record<string, string>; required: string[] };
  capabilities: { effects: string[]; egress: string; sensitivity: string };
}

export interface Manifest {
  digest: string;
  tools: ManifestTool[];
}

export interface ManifestChange {
  tool: string;
  kind: string;
  severity: "escalation" | "change" | "reduction";
  summary: string;
  diff?: string[];
}

export interface Inspection {
  source: string;
  drift: string | null;
  approved_digest: string;
  observed_digest: string;
  activate: boolean;
  status: string;
  changes: ManifestChange[];
  note: string;
}

export interface ManifestInfo {
  approved: Manifest;
  drift_examples: Record<string, string>;
}
