# ADR 0001: Architecture for the NecroShield arena

Status: accepted (2026-11-24). This record shows what was decided and later revised. `docs/architecture.md` describes the system as built.

### Framework-free core
The domain core (`backend/necroshield/`) uses only the standard library: frozen dataclasses for contracts and `sqlite3` for local storage. This keeps policy, replay, and evidence logic testable in any environment. Pydantic models will validate HTTP input at the FastAPI boundary and convert to the core contracts. SQLAlchemy/Alembic will own the PostgreSQL schema, and the current SQLite store will become the local adapter.

## Decisions

### Agent execution: typed state machine, not LangGraph
Fixture agents need to be deterministic and replayable. A typed state machine (`read_source -> propose_actions -> act -> report`) with a fixed step bound gives that with no extra dependency. LangGraph adds a graph runtime and checkpointing we don't need for fixtures. If a stochastic model track is added later, LangGraph can be reconsidered for that track only.

### Policy: in-process default-deny capability engine, not OPA/Rego
A policy is a list of capability grants: tool name, argument constraints (exact values, allowed resource IDs, destination allowlist). The gateway evaluates it before dispatch and denies anything not granted. This avoids a second runtime and keeps decisions testable with Hypothesis. Tradeoff: no Rego ecosystem or external policy tooling. The policy is a versioned, frozen dataclass with a JSON form; Pydantic validates it only at the API edge.

### Replay mode: `deterministic_intent_replay`
The agent's proposed actions are produced once from the scenario. The same list is dispatched in a fresh baseline environment (no gateway checks) and a fresh protected environment (gateway on). Results say what the gateway does with identical intents. They do not say how a particular model behaves.

### Outcome evaluation
Attack success means a synthetic effect occurred: a canary string reached the in-memory sink, an out-of-scope tool executed, or a protected memory key changed. Task utility means the generated report contains the values from the synthetic invoice. Neither uses model judgment.

### Evidence
Events are redacted first, then hashed: `hash = sha256(prev_hash || canonical_json(event))`. Exports include the scenario version, policy version, and event chain. A standalone verifier script recomputes the chain without importing application code. The chain detects edits to individual events. It does not prove authorship, because anyone who can rewrite the whole chain can recompute it. Signing is out of scope for now.

### Stack (revised)
As built: Next.js, TypeScript, React Flow, plain CSS; FastAPI and Pydantic; SQLite; the official MCP SDK; pytest, Hypothesis, and Playwright. Tailwind, SQLAlchemy, Alembic, and PostgreSQL were planned and then dropped. A single-instance demo with a verify-on-read evidence log does not need them. Redis and a job queue are not justified: a fixture pair runs in about a millisecond.

### Isolation
Tools only touch in-memory objects. No tool opens a socket, spawns a process, or reads outside a synthetic fixture. The limits actually enforced are: argument and output size limits, the agent's 32-step bound, and the live loop's turn, call, and time budgets. There are no separate worker processes and no per-run memory limit; runs execute in the API process. The container adds a non-root user but is not the isolation boundary.

## Threat boundaries
In scope: synthetic documents and tool responses containing inert injection text; unauthorized tool calls; synthetic exfiltration to a local sink; privilege-boundary and memory-poisoning attempts.
Out of scope: real targets, real credentials, arbitrary commands, and any outbound network call.

## Originality
The project must be started on or after October 30, 2026. This code was written from scratch on 2026-11-24, inside the October 30 to December 4, 2026 window, and is intended for a new repository. A separate earlier NecroShield build exists at `leninathikam/necroshield` (first commit 2026-11-17). None of its code was copied or read for this implementation.
