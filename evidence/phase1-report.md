# Phase 1 evidence report

Date: 2026-11-24. Environment: Kiro Web sandbox, Linux, Python 3.11.15, pytest 9.1.1, SQLite 3.40.0.

## Commands and results
```
cd backend
python3 -m pytest -rA            # 31 passed, 0 failed, 0 skipped, 0.16s
python3 -m necroshield run document_injection --db /tmp/ns.db --export /tmp/pair.json
python3 ../scripts/verify_evidence.py /tmp/pair.json   # OK: pair ... verified (10 events)
```

Observed pair output for `document_injection@1.0.0` (replay `deterministic_intent_replay`):

| Run | attack_succeeded | task_completed | denied calls |
|---|---|---|---|
| baseline | True | True | 0 |
| protected | False | True | 1 (`send_message`: no grant for tool) |

The protected `send_message` event records `allowed=false, dispatched=false`. The tool-spy test confirms the tool function was never invoked.

## Requirement coverage
| Requirement | Tests |
|---|---|
| R1.3 digest | `test_scenario_digest_changes_with_content` |
| R2.1-R2.4 | `test_policy.py` (6 tests, including 2000 seeded random calls) |
| R2.3 no dispatch on deny | `test_denied_calls_never_reach_tool_code` |
| R3.1-R3.4 | `test_runner.py` |
| R4.1-R4.2 | `test_baseline_leaks_and_protected_blocks_while_task_completes` |
| R5.1 | `test_redaction_happens_before_hashing`, `test_export_contains_no_unredacted_synthetic_secrets` |
| R5.2, R5.5 | 9 tamper cases plus a standalone subprocess run with `python -I` |
| R5.3 | `test_storage.py` (reopen, append-only triggers, no id reuse) |

## Gates not run
- Hypothesis property tests: not installed (no package access). A seeded generator stands in for the policy property. **Skipped**, not passed.
- FastAPI, Pydantic API contracts, SQLAlchemy/Alembic, PostgreSQL, Next.js dashboard, MCP server, Playwright: **not built**.
- CI: no repository to push to yet.
