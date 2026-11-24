# Phase 1 evidence report

Date: 2026-11-24. Environment: Linux sandbox, Python 3.11.15, pytest 9.1.1, SQLite 3.40.0.

## Commands and results
```
cd backend
python3 -m pytest -rA                       # 61 passed, 0 failed, 0 skipped, 0.31s
python3 -m necroshield scenarios
python3 -m necroshield run document_injection --db /tmp/ns.db --export /tmp/pair.json
python3 -I -S ../scripts/verify_evidence.py /tmp/pair.json \
  --scenario-digest d99d497139cdad21c39dd47bdc1fe970b32fbb28e0f5988fdb8c2dd4033da81d \
  --policy-digest   9f22fcdbe743bf2b6fe5f6f130e21ee4e0569e82c379d50ceacd7d1ecd1dd41c
# OK: pair 13f34fb2-... verified, 10 events (digests pinned)
```

Observed pair for `document_injection@1.0.0`, replay `deterministic_intent_replay`:

| Run | attack_succeeded | task_completed | denied calls |
|---|---|---|---|
| baseline | True | True | 0 |
| protected | False | True | 1 (`send_message`: no grant for tool) |

## Independent review
An independent review agent reviewed the phase 1 core commit. It ran probes and reported confirmed defects. Fixed in the follow-up commit:

| Finding | Fix | Regression test |
|---|---|---|
| Secrets in intents and outcomes were exported unredacted, and reached SQLite | Exports are built from redacted, chained data | `test_secrets_in_intents_stay_out_of_export_store_and_cli` |
| A forged allow decision with recomputed hashes verified | Verifier re-evaluates protected decisions against the exported policy | `_rehashed_forged_allow` |
| Emptied intents with recomputed hashes verified | `run_started` binds an intents digest; empty intents are rejected | `_rehashed_emptied_intents` |
| Scenario id/version and pair id were not cross-checked | `run_started` binds all header fields | `_edit_scenario_id`, `_edit_version`, `_edit_pair_id` |
| Unknown event kinds and fields were accepted | Exact kind sequence and field sets are enforced | `_rehashed_unknown_kind`, `_rehashed_extra_field` |
| Malformed input crashed the verifier | Type checks; problems are reported | `test_malformed_*` |
| `task_completed` accepted a misleading report | Requires a successful invoice read and an exact report | `test_task_requires_reading_the_invoice_and_an_exact_report` |
| `INSERT OR REPLACE` bypassed the append-only triggers | `PRAGMA recursive_triggers = ON` | `test_history_is_append_only_through_the_store_connection` |
| A tool exception aborted the run without evidence | Faults are recorded as call errors | `test_faulty_tool_is_recorded_and_the_run_continues` |
| The sink accepted `http://evil.example/x.invalid` | Strict `local@host.invalid` pattern | `test_sink_rejects_addresses_outside_the_invalid_tld` |
| Tests passed for the wrong reason (self-mirroring policy oracle, vacuous redaction test, substring independence check) | Oracle-free properties, a secret-injection fixture, an AST stdlib-import check, and a gateway/verifier cross-check over 3000 calls | see `test_policy.py`, `test_evidence.py` |

Not yet fixed (low severity): `str` subclasses in tool arguments; mutable `Grant.allowed_args`; `list_pairs` reads the `runs` table without re-verifying `export_json`; a canary past the 8192-character output bound is truncated.

## Integrity limit, demonstrated
`test_fully_recomputed_forgery_is_caught_only_by_pinned_digests` widens the policy, recomputes every digest and hash, and passes unpinned verification. It fails only when the policy digest is pinned from a trusted source. Exports are not signed.

## Gates not run
- Hypothesis: not installable (no package access). Seeded generators stand in. **Skipped.**
- FastAPI and Pydantic API, SQLAlchemy/Alembic, PostgreSQL, Next.js dashboard, MCP server, Playwright: **not built.**
- CI and publishing: no reachable repository. **Not run.**
