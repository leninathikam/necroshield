"""Default-deny capability policy. Pure function: no side effects, no tool access."""

from __future__ import annotations

from .contracts import Decision, ToolCall
from .scenarios import Grant, Policy


def _check_grant(grant: Grant, call: ToolCall) -> str | None:
    """Return a denial reason, or None when the grant covers the call exactly."""
    extra = set(call.args) - set(grant.allowed_args)
    if extra:
        return f"arguments not granted: {sorted(extra)}"
    for name, allowed in grant.allowed_args.items():
        if name in call.args and allowed is not None and call.args[name] not in allowed:
            return f"{name}={call.args[name]!r} outside granted scope"
    # A scoped argument must be present with an allowed value. Unscoped (null) arguments may be
    # omitted; the tool then rejects a missing required one itself.
    missing = sorted(n for n, v in grant.allowed_args.items() if v is not None and n not in call.args)
    if missing:
        return f"missing argument: {missing}"
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
