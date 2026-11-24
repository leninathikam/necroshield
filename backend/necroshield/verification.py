"""Loads the standalone verifier (scripts/verify_evidence.py) so the application checks stored
evidence with the same independent code a third party would run. The verifier never imports the
application; the application imports the verifier."""

from __future__ import annotations

import importlib.util
import os
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "verify_evidence.py"


@lru_cache(maxsize=1)
def verifier() -> ModuleType:
    path = Path(os.environ.get("NECROSHIELD_VERIFIER", DEFAULT_PATH))
    spec = importlib.util.spec_from_file_location("necroshield_standalone_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"standalone verifier not found at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_export(export: Any, scenario_digest: str | None = None, policy_digest: str | None = None,
                  pins: dict[str, dict[str, str]] | None = None) -> list[str]:
    return verifier().verify_any(export, scenario_digest, policy_digest, pins)
