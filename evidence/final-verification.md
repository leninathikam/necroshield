# Final verification (2026-11-24)

Every result below was observed directly: locally in the Kiro Web sandbox (Python 3.11.15, standard library and pytest only), or in GitHub Actions on `leninathikam/necroshield`. Nothing is extrapolated.

## Gates
| Gate | Where | Result |
|---|---|---|
| Core suite (stdlib) | sandbox: `cd backend && python3 -m pytest -q -o addopts=""` | 135 passed, 4 skipped (the skipped modules need fastapi, mcp, httpx, and hypothesis, which the sandbox cannot install) |
| Core suite, Python 3.11, 3.12, 3.13, 3.14 | CI `core` | pass on all four |
| Full backend suite with API, MCP SDK, live loop, Hypothesis | CI `api` (skips fail the job) | **178 passed, 0 skipped** (run for `17eb3f0`) |
| Benchmark, 7 pinned pair verifications, pinned bundle verification | CI `evidence` | all `OK ... (digests pinned)`; bundle: `7 pairs, summary recomputed` |
| Frontend lint, typecheck, production build, `npm audit --omit=dev --audit-level=high` | CI `frontend` | pass |
| Playwright, desktop (1440×900) and mobile (Pixel 7), against the real API | CI `e2e` | **18 passed** |
| Container build, health, static pages, one verified run, non-root uid | CI `container` | `container judge path OK` |
| pip-audit on the pinned set; gitleaks over full history | CI `security` | pass (gitleaks allowlists only synthetic canary shapes) |
| Desktop and mobile visual inspection | Playwright screenshots in `.kiro/artifacts/screens/` | Reviewed. Panel misalignment, graph node chrome and clipping, the stale dashboard, and mobile overlap were found and fixed in `17eb3f0` and `dca45a5` |
| PostgreSQL integration | n/a | **Not applicable.** The deployed store is SQLite (see `docs/architecture.md`). No PostgreSQL adapter exists. |
| Real-model (live) evaluation | n/a | **Not run.** No provider credentials. The loop is tested only with a scripted transport double. |
| Public deployment | n/a | **Not done.** No hosting credentials are available in this environment. |

## Fixture benchmark (`deterministic_intent_replay`, scenarios v2.0.0)
| Metric | Baseline | Protected |
|---|---|---|
| Attack success | 6/6 | 0/6 |
| Task completion | 6/7 | 7/7 |
| False positives | n/a | 0/1 |
| Denial rate | n/a | 6/36 |
| Cost | null | null |

Every protected denial is decisive: lifting any single denial restores its attack (`test_every_protected_denial_is_decisive`).

Reproduce:
```
cd backend
python -m necroshield benchmark
python -m necroshield scenarios --pins > pins.json
```
Then download `/api/benchmark/bundle` and run `python ../scripts/verify_evidence.py bundle.json --pins pins.json`.

## Audit findings fixed in this pass
### Initial audit (from the brief)
| Finding | Fix | Test |
|---|---|---|
| Grants and policies were mutable after their digest was taken | `MappingProxyType` and tuples; validated at construction | `test_scenario_definitions_are_immutable` |
| `ToolCall` accepted `str` subclasses, unchecked argument names, and control characters | exact type, identifier, size, and character checks | `test_non_canonical_arguments_are_rejected_at_construction` |
| `tools.invoke` was public, so callers could bypass the gateway | private `_invoke` and `_fn`; AST tests | `test_only_the_gateway_references_tool_dispatch`, `test_g1_*` |
| Tools ignored extra arguments | argument specs enforced | `test_tools_reject_unexpected_and_missing_arguments` |
| Silent truncation could hide a canary | over-limit output is an error | `test_oversized_output_is_an_explicit_error_not_a_truncation` |
| Invalid scenarios and policies were accepted | fail-closed construction | `test_invalid_scenarios_fail_closed`, `test_invalid_policies_and_checks_fail_closed` |
| Stored evidence was shown unverified | verify on every read; outcomes withheld otherwise | `test_tampering_with_the_database_file_is_reported_on_load` |
| NaN was allowed in canonical JSON | `allow_nan=False`; no floats in hashed events | `test_non_json_values_are_rejected_from_evidence` |
| Hashes could differ across Python versions | golden vector | `test_golden_hash_vector_is_stable_across_python_versions` |
| The agent could not see tool output (no tool-response injection was possible) | plans against a disposable environment; late binding | `test_agent_sees_injections_in_tool_responses`, `test_placeholders_bind_from_each_runs_own_observations` |

### Independent review 2 (28 findings)
Fixed, with a test for each (`backend/tests/test_review_regressions.py`, `test_api.py`, `test_live.py`):

| ID | Finding | Fix |
|---|---|---|
| V1 | Outcomes, bound arguments, and effects were not re-derived | Per-call effects are chained; the verifier replays them, recomputes bound arguments, and enforces strict types |
| V2 | Scenario header not bound to the digest | Digest = H(header digest, body digest); the header is exported in full |
| V3 | Pins were silently ignored for bundles | Single-pair flags rejected for bundles and live runs; `--pins` file added |
| V4 | Bundle subsets and relabelled policy sources verified | Pinned bundles must be complete and match default-policy digests |
| V5 | Live metadata was unbound | Provider, model, temperature, usage, scenario, and cost are checked against chained values |
| V6 | A lone surrogate crashed the verifier | Reported as malformed; floats rejected |
| R1, R2 | Secret-shaped policy and check values | Rejected at construction, so redaction and enforcement always see the same values |
| A1 | Rate-limit key spoofable through forwarded headers | Container trusts `X-Forwarded-For` only from `FORWARDED_ALLOW_IPS` (default `127.0.0.1`); limiter evicts idle keys |
| A2 | Unbounded growth and unindexed queries | Indexes added; `NECROSHIELD_MAX_PAIRS` cap (507 when full) |
| A3 | One bad row caused 500s on the list endpoints | Rows that fail to parse become problems; summaries hidden |
| A4 | Stored columns and heads were never checked | Cross-checked on read |
| A5 | Streamed oversized bodies | 413 enforced while streaming; test added |
| A6 | CSP blocked the Swagger UI | Swagger disabled; inline-script limit documented |
| A7 | Unthrottled reads; stale definitions in the benchmark | Read bucket added; population filtered by current digests; scenario views cached |
| L1, L2 | Malformed or hostile provider output crashed the loop | Response shape validated; model text sanitized before hashing |
| L3 | No global live budget | One live run at a time; per-process run budget |
| G1 | Tool functions and the decision override were public | Private names; AST test confines them |
| F1 | Injected lines were never highlighted | Regex no longer consumes the line break; test checks whole-line matches |
| F2 | The live option could not launch | Wired to `/api/live/runs`, with per-run verification shown |
| F3 | UI and API claimed every result was verified | Wording narrowed; MCP transcripts labeled "not hash-chained" |
| F4, F5, F6 | Graph labels, ARIA roles, picker, error prefix | Fixed |
| D1 | Documentation claims the code did not support | ADR, threat model, and compliance notes corrected |

Accepted and documented, not fixed:
- **L4:** the live prompt is tied to the shared invoice fixture.
- **A8:** the origin check does not authenticate anyone.
- **Unverifiable fields:** denial reasons and attachment-derived message bodies are recorded but not re-derived.

## Not implemented
- Public hosting. The `Dockerfile` and `render.yaml` are ready; credentials are needed.
- Real-model runs. The adapter is ready; it needs a provider key and a budget.
- PostgreSQL. SQLite was chosen on purpose for a single-instance demo.
- Signed evidence. Integrity relies on pinned digests.
- The demo video. The participant must record it from `docs/demo-script.md`.
