"""Strict contracts at API, tool, and evidence boundaries."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolCall(StrictModel):
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any]


class ScenarioInfo(StrictModel):
    id: str
    name: str
    description: str
    category: str
    severity: Literal["critical", "high", "medium", "control"]
    version: str
    task: str
    is_attack: bool
    source: Literal["document", "tool_response", "control"]


class Event(StrictModel):
    sequence: int
    kind: str
    tool: str | None = None
    decision: Literal["allow", "deny", "bypass"] | None = None
    reason: str
    message: str
    arguments: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    previous_hash: str
    hash: str
    timestamp: datetime


class Metrics(StrictModel):
    attack_success: bool
    blocked_executions: int
    legitimate_task_completed: bool
    false_positives: int
    latency_ms: float
    tool_calls: int
    cost_usd: float | None = None


class Run(StrictModel):
    id: str
    mode: Literal["baseline", "protected"]
    status: Literal["completed", "failed"]
    events: list[Event]
    metrics: Metrics
    output: str
    effects: dict[str, Any]


class RunPair(StrictModel):
    id: str
    scenario_id: str
    scenario_name: str
    scenario_version: str
    scenario_digest: str
    policy_version: str
    created_at: datetime
    replay_mode: Literal["deterministic_intent_replay"] = "deterministic_intent_replay"
    execution_kind: Literal["synthetic_fixture"] = "synthetic_fixture"
    intent_tape_digest: str
    baseline: Run
    protected: Run


class CreateRun(StrictModel):
    scenario_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9-]+$")


class Benchmark(StrictModel):
    id: str
    created_at: datetime
    execution_kind: Literal["synthetic_fixture"] = "synthetic_fixture"
    total_scenarios: int
    attack_scenarios: int
    control_scenarios: int
    baseline_attack_success_rate: float
    protected_attack_success_rate: float
    protected_task_completion_rate: float
    false_positive_rate: float
    blocked_executions: int
    latency_ms: float
    cost_usd: float | None = None
    pair_ids: list[str]
