# Design: Phase 1 vertical slice

See docs/adr/0001-architecture.md for the decisions behind this design.

## Modules (backend/necroshield/)
| Module | Responsibility | Requirements |
|---|---|---|
| `contracts.py` | Frozen dataclasses: `ToolCall`, `Decision`, `Event`. Validate at construction. | R2, R5 |
| `scenarios.py` | Scenario registry and `document_injection` v1. Canonical digest. | R1 |
| `tools.py` | `Environment` (fresh in-memory state) and bounded mock tools. | R3.2 |
| `policy.py` | Default-deny capability grants and `evaluate()`. | R2 |
| `agent.py` | Naive fixture agent as a bounded state machine. Produces intents. | R3.1 |
| `runner.py` | Dispatches intents in baseline and protected modes. | R2.3, R3 |
| `evaluator.py` | Derives outcomes from environment state only. | R4 |
| `evidence.py` | Redaction, hash chain, export. | R5.1, R5.2, R5.4 |
| `storage.py` | SQLite persistence (stdlib `sqlite3`) behind a small repository. | R5.3 |
| `scripts/verify_evidence.py` | Standalone verifier. | R5.5 |

## Pair flow
1. `agent.plan(scenario)` runs the state machine `read_source -> extract -> follow_instructions -> report`, capped at 16 steps, and returns a tuple of `ToolCall`.
2. For each mode, `runner` builds `Environment.from_scenario(scenario)`.
3. Baseline dispatches every call. Protected calls `policy.evaluate` first and dispatches only on allow.
4. `evaluator` inspects the environment's sink and reports.
5. `evidence` redacts, then hash-links the events.

## Hash chain
`hash_i = sha256(hash_{i-1} + canonical_json(event_i without hash))`, with genesis `"0" * 64`. Canonical JSON uses sorted keys and compact separators. The export carries a `head` hash. The verifier recomputes every link and checks that `seq` runs 0..n-1.

Limit: anyone who can rewrite the full export can recompute the chain. The chain detects partial edits, not a full forgery. Signing is future work.

## Framework boundary
The core uses only the standard library, so it can be tested without network package installs. FastAPI, Pydantic API contracts, SQLAlchemy/Alembic, and the UI wrap this core in later tasks.
