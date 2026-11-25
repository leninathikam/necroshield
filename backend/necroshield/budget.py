"""Spending guard for live-model experiments.

Before each run, the worst-case cost of that run (from configured list prices and the loop's
token bounds) is reserved against the budget; a run that could exceed it does not start. After
the run, the ledger records the provider-reported cost when available, otherwise the estimate
from usage and prices. The ledger is a JSON file so the cap survives across invocations.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .live import ProviderConfig, worst_case_run_cost

DEFAULT_BUDGET_USD = 2.0


class BudgetExceeded(Exception):
    pass


@dataclass
class Ledger:
    path: Path
    budget_usd: float

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"spent_usd": 0.0, "runs": []}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data.get("spent_usd"), (int, float)) or not isinstance(data.get("runs"), list):
            raise ValueError(f"ledger {self.path} is malformed; refusing to spend")
        return data

    @property
    def spent(self) -> float:
        return float(self._read()["spent_usd"])

    def reserve(self, config: ProviderConfig) -> float:
        if config.price_in_per_mtok is None or config.price_out_per_mtok is None:
            raise BudgetExceeded("set NECROSHIELD_LLM_PRICE_IN_PER_MTOK and _OUT_PER_MTOK: cost cannot be bounded without prices")
        worst = worst_case_run_cost(config.price_in_per_mtok, config.price_out_per_mtok)
        if self.spent + worst > self.budget_usd:
            raise BudgetExceeded(f"budget ${self.budget_usd:.2f}: spent ${self.spent:.4f}, next run could cost up to ${worst:.4f}")
        return worst

    def record(self, run: dict[str, Any]) -> float:
        charged = run.get("provider_reported_cost_usd")
        estimated = run.get("cost_usd")
        actual = float(charged if charged is not None else (estimated or 0.0))
        data = self._read()
        data["spent_usd"] = round(float(data["spent_usd"]) + actual, 8)
        data["runs"].append({"run_id": run["run_id"], "at": datetime.now(timezone.utc).isoformat(),
                             "scenario": run["scenario"]["id"], "model": run["provider"]["model"],
                             "provider_reported_cost_usd": charged, "estimated_cost_usd": estimated,
                             "recorded_usd": actual})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        return actual
