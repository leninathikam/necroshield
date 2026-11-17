"""Validate this project's documented Kiro config subset; not Kiro's official validator."""

from __future__ import annotations

import json
from pathlib import Path
import re


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    hooks = json.loads((root / ".kiro/hooks/focused-checks.json").read_text(encoding="utf-8"))
    require(hooks["version"] == "v1", "Hook version must be v1")
    require(len(hooks["hooks"]) == 2, "Expected backend and frontend hooks")
    for hook in hooks["hooks"]:
        require(hook["trigger"] == "PostFileSave", "Only documented PostFileSave is configured")
        re.compile(hook["matcher"])
        require(hook["action"]["type"] == "command", "Fixed command action required")
        require(hook["action"]["command"].startswith("python .kiro/scripts/focused_checks.py "), "Hook command must use fixed runner")
        require(hook["timeout"] == 120, "Hook timeout must remain bounded")
    backend_pattern = re.compile(hooks["hooks"][0]["matcher"])
    require(bool(backend_pattern.search("backend/necroshield/policy.py")), "Backend matcher must accept POSIX paths")
    require(bool(backend_pattern.search(r"backend\necroshield\policy.py")), "Backend matcher must accept Windows paths")
    agent = json.loads((root / ".kiro/agents/security-reviewer.json").read_text(encoding="utf-8"))
    require(agent["tools"] == ["read", "@necroshield-inspector/list_benchmarks", "@necroshield-inspector/inspect_run"], "Reviewer must expose only read and exact inspector tools")
    require(agent["includeMcpJson"] is False, "Reviewer must not inherit unknown MCP tools")
    require({"capability": "fs_write", "effect": "deny"} in agent["permissions"]["rules"], "Reviewer must deny writes")
    mcp = json.loads((root / ".kiro/settings/mcp.json").read_text(encoding="utf-8"))
    server = mcp["mcpServers"]["necroshield-inspector"]
    require(server["command"] == "uv", "Inspector must use project-local dependency environment")
    require(server["args"] == ["run", "--directory", "backend", "python", "-m", "necroshield.mcp_server"], "Inspector launch must be fixed")
    require(server["autoApprove"] == ["list_benchmarks", "inspect_run"], "Only read-only inspector calls may auto-approve")
    require(server["disabledTools"] == ["read_synthetic_invoice", "sandbox_tool_call"], "Workspace inspector must hide fixture execution tools")
    for file in (root / ".kiro/steering").glob("*.md"):
        require(file.read_text(encoding="utf-8").startswith("---\ninclusion: "), f"Missing steering inclusion in {file.name}")
    for name in ("requirements.md", "design.md", "tasks.md"):
        require((root / ".kiro/specs/necroshield" / name).is_file(), f"Missing spec {name}")
    print("PASS: documented Kiro hook, agent, steering, and spec contracts")
    print("LIMIT: official Kiro CLI validation and Kiro hook execution still require installed Kiro")


if __name__ == "__main__":
    main()
