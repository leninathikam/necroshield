"""One policy-to-dispatch boundary used by the arena and the SDK MCP surface."""

from .contracts import ToolCall
from .evidence import Trace
from .policy import TrustedScope, authorize
from .tools import SyntheticWorld


class Gateway:
    def __init__(self, world: SyntheticWorld, trace: Trace, *, protected: bool):
        self.world, self.trace, self.protected = world, trace, protected
        self.scope = TrustedScope()
        self.blocked = 0
        self.false_positives = 0

    def call(self, call: ToolCall) -> dict:
        decision = authorize(call, self.scope)
        action = ("allow" if decision.allowed else "deny") if self.protected else "bypass"
        self.trace.append(kind="policy.decision", tool=call.tool, decision=action,
            arguments=call.arguments, reason=decision.rule if self.protected else "baseline.policy-bypassed",
            message=decision.reason if self.protected else "Baseline bypasses authorization inside the bounded synthetic catalogue")
        if self.protected and not decision.allowed:
            self.blocked += 1
            self.false_positives += int(call.tool in {"document.read", "report.write"})
            return {"executed": False, "decision": "deny", "reason": decision.reason}
        result = self.world.execute(call)
        self.trace.append(kind="tool.executed", tool=call.tool, arguments=call.arguments,
            result=result, reason="dispatcher.executed", message=f"Executed {call.tool} in memory")
        return {"executed": True, "decision": action, "result": result}
