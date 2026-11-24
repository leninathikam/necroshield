"""Default-deny capability policy evaluated before any tool dispatch."""

from __future__ import annotations

from .contracts import Decision, ToolCall
from .scenarios import Grant, Policy


def _check_grant(grant: Grant, call: ToolCall) -> str | None:
    """Return a denial reason, or None when the grant covers the call."""
    extra = set(call.args) - set(grant.allowed_args)
    if extra:
        return f"arguments not granted: {sorted(extra)}"
    for name, allowed in grant.allowed_args.items():
        if name not in call.args:
            return f"missing argument: {name}"
        if allowed is not None and call.args[name] not in allowed:
            return f"{name}={call.args[name]!r} outside granted scope"
    return None


def evaluate(policy: Policy, call: ToolCall) -> Decision:
    grants = [g for g in policy.grants if g.tool == call.tool]
    if not grants:
        return Decision(False, f"no grant for tool {call.tool}")
    reasons = []
    for grant in grants:
        reason = _check_grant(grant, call)
        if reason is None:
            return Decision(True, "granted", grant.grant_id)
        reasons.append(f"{grant.grant_id}: {reason}")
    return Decision(False, "; ".join(reasons))
