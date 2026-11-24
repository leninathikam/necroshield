# ADR 0001: Architecture for the NecroShield arena

Status: accepted for the Phase 1 core (implemented and tested 2026-11-24). Decisions about the API, database, UI, and MCP server are still proposed.

### Framework-free core
The domain core (`backend/necroshield/`) uses only the standard library: frozen dataclasses for contracts and `sqlite3` for local storage. This keeps policy, replay, and evidence logic testable in any environment. Pydantic models will validate HTTP input at the FastAPI boundary and convert to the core contracts. SQLAlchemy/Alembic will own the PostgreSQL schema, and the current SQLite store will become the local adapter.

## Decisions

### Agent execution: typed state machine, not LangGraph
Fixture agents need to be deterministic and replayable. A typed state machine (`read_source -> propose_actions -> act -> report`) with a fixed step bound gives that with no extra dependency. LangGraph adds a graph runtime and checkpointing we don't need for fixtures. If a stochastic model track is added later, LangGraph can be reconsidered for that track only.

### Policy: in-process default-deny capability engine, not OPA/Rego
A policy is a list of capability grants: tool name, argument constraints (exact values, allowed resource IDs, destination allowlist). The gateway evaluates it before dispatch and denies anything not granted. This avoids a second runtime and keeps decisions testable with Hypothesis. Tradeoff: no Rego ecosystem or external policy tooling. The policy format is a versioned Pydantic model, so it can be exported to Rego later.

### Replay mode: `deterministic_intent_replay`
The agent's proposed actions are produced once from the scenario. The same list is dispatched in a fresh baseline environment (no gateway checks) and a fresh protected environment (gateway on). Results say what the gateway does with identical intents. They do not say how a particular model behaves.

### Outcome evaluation
Attack success means a synthetic effect occurred: a canary string reached the in-memory sink, an out-of-scope tool executed, or a protected memory key changed. Task utility means the generated report contains the values from the synthetic invoice. Neither uses model judgment.

### Evidence
Events are redacted first, then hashed: `hash = sha256(prev_hash || canonical_json(event))`. Exports include the scenario version, policy version, and event chain. A standalone verifier script recomputes the chain without importing application code. The chain detects edits to individual events. It does not prove authorship, because anyone who can rewrite the whole chain can recompute it. Signing is out of scope for now.

### Stack
Next.js, TypeScript, Tailwind, React Flow; FastAPI, Pydantic, SQLAlchemy, Alembic; PostgreSQL (SQLite locally); official MCP SDK; pytest, Hypothesis, Playwright. Redis and a job queue are not justified yet: fixture runs finish in milliseconds. Add them only when a run exceeds a request timeout.

### Isolation
Mock tools only touch in-memory objects. No tool opens a socket, spawns a process, or reads outside a synthetic fixture. Fixture workers get time, memory, and output limits. A container is an additional layer and not the isolation boundary.

## Threat boundaries
In scope: synthetic documents and tool responses containing inert injection text; unauthorized tool calls; synthetic exfiltration to a local sink; privilege-boundary and memory-poisoning attempts.
Out of scope: real targets, real credentials, arbitrary commands, and any outbound network call.

## Originality
The project must be started on or after October 30, 2026. This code was written from scratch on 2026-11-24, inside the October 30 to December 4, 2026 window, and is intended for a new repository. A separate earlier NecroShield build exists at `leninathikam/necroshield` (first commit 2026-11-17). None of its code was copied or read for this implementation.
