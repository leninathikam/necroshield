# Design: web platform

Full module map: `docs/architecture.md`. Threats and controls: `docs/threat-model.md`.

## Key design points
- **Late binding (R7, R10).** Fixture intents are templates. `$number`, `$total`, and `$payee` bind from each run's own tool outputs, so a blocked memory poisoning does not leak the poisoned value into the protected run's report. The intents stay identical across runs.
- **Gateway as choke point (R6.4, R9.2).** The runner, the planning pass, the MCP server, and the live loop all call `Gateway.execute`. An AST test fails if any other module references `_invoke`.
- **Verify on read (R8.2).** `RunStore` returns verification problems with every stored pair. The API puts the outcome fields only in verified summaries.
- **Counterfactual attribution (R10.2).** For each denied intent, rerun with only that decision lifted and compare outcomes. The fixture is deterministic, so the result is exact.
- **Separate live format (R11).** `necroshield.live/1` carries its own chain. The verifier checks its integrity and enforcement, but never pairs it with another run.
- **Pins resolved by CI (R14).** The sandbox has no package index, so CI resolved the current versions, `pip-audit` and `npm audit` checked them, and the resolved sets were committed as `constraints.txt` and `package-lock.json`.

## Requirement → code → test
| Req | Code | Tests |
|---|---|---|
| R6 | `contracts.py`, `scenarios.py`, `tools.py`, `gateway.py`, `evidence.py` | `test_policy.py`, `test_scenarios.py`, `test_evidence.py` (golden vector) |
| R7 | `catalog.py` | `test_scenarios.py::test_scenario_outcomes[*]` |
| R8 | `api/app.py`, `api/guards.py`, `api/schemas.py` | `test_api.py` |
| R9 | `mcp_server.py` | `test_mcp.py`, `test_api.py::test_mcp_replay_endpoint` |
| R10 | `runner.decisive_denials`, Policy Inspector | `test_every_protected_denial_is_decisive`, e2e policy counterfactual |
| R11 | `live.py` | `test_live.py` (scripted test double; mechanics only) |
| R12 | `metrics.py`, verifier `verify_bundle` | `test_api.py::test_benchmark_and_bundle`, e2e benchmark |
| R13 | `frontend/` | `frontend/e2e/app.spec.ts` (desktop and mobile) |
| R14 | `.github/workflows/ci.yml`, `Dockerfile` | CI jobs `container`, `security` |
