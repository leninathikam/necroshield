"""The only route from an intended call to tool code.

The runner, the fixture agent's planning pass, the live-model loop, and the MCP server all execute
tools through a Gateway. With a policy, every call is evaluated first and a denied call never
reaches `tools._invoke`. Without a policy (baseline), calls are dispatched unchecked.
"""

from __future__ import annotations

from .contracts import Decision, DispatchRecord, ToolCall
from .policy import evaluate
from .scenarios import Policy
from .tools import Environment, ToolError, _invoke

UNCHECKED = Decision(True, "baseline: no policy enforcement")


class Gateway:
    def __init__(self, env: Environment, policy: Policy | None) -> None:
        self.env = env
        self.policy = policy

    def decide(self, call: ToolCall) -> Decision:
        return evaluate(self.policy, call) if self.policy is not None else UNCHECKED

    def execute(self, call: ToolCall, decision: Decision | None = None) -> DispatchRecord:
        decision = decision if decision is not None else self.decide(call)
        if not decision.allowed:
            return DispatchRecord(call, decision, dispatched=False)
        try:
            return DispatchRecord(call, decision, dispatched=True, output=_invoke(self.env, call.tool, call.args))
        except ToolError as exc:
            return DispatchRecord(call, decision, dispatched=True, error=str(exc))
        except Exception as exc:  # A faulty tool must not abort the run or skip its evidence event.
            return DispatchRecord(call, decision, dispatched=True, error=f"tool fault: {type(exc).__name__}")
