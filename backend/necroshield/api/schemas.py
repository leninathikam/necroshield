"""Strict request contracts. Unknown fields are rejected; values are converted into the core's
validated types, which fail closed on anything the core does not accept."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..scenarios import Policy

ScenarioId = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class GrantIn(Strict):
    grant_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    tool: str = Field(max_length=64)
    allowed_args: dict[str, list[str] | None] = Field(max_length=8)


class PolicyIn(Strict):
    version: str = Field(min_length=1, max_length=64)
    grants: list[GrantIn] = Field(max_length=32)

    def to_policy(self) -> Policy:
        return Policy.from_dict(self.model_dump())


class RunRequest(Strict):
    scenario_id: str = ScenarioId
    policy: PolicyIn | None = None


class ApproveRequest(Strict):
    strategy: str = Field(pattern=r"^[a-z_]{1,32}$")


class VerifySignedRequest(Strict):
    document: dict[str, Any]
    public_key: str = Field(min_length=44, max_length=64)


class McpDemoRequest(Strict):
    scenario_id: str = ScenarioId
    mode: Literal["baseline", "protected"] = "protected"
    drift: str | None = Field(default=None, pattern=r"^[a-z_]{1,32}$")
    approve_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class McpInspectRequest(Strict):
    drift: str | None = Field(default=None, pattern=r"^[a-z_]{1,32}$")
    approve_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class LiveRunRequest(Strict):
    scenario_id: str = ScenarioId
    mode: Literal["baseline", "protected"] = "protected"
    repetitions: int = Field(default=1, ge=1, le=3)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
