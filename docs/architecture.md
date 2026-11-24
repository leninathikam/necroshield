# Architecture

NecroShield runs adversarial scenarios against an agent's tool use inside a synthetic environment, and measures what a pre-dispatch policy changes. All state is in memory and synthetic; nothing reaches a real system.

```
 browser ──HTTP──▶ FastAPI (api/app.py) ──▶ runner ──▶ Gateway ──▶ tools._invoke ──▶ in-memory Environment
   ▲   static export      │   guards: origin, body limit, rate limit, headers
   │                      ├──▶ mcp_server (official MCP SDK) ──▶ Gateway ──▶ tools
   │                      ├──▶ live (OpenAI-compatible adapter, optional) ──▶ Gateway ──▶ tools
   │                      └──▶ storage (SQLite, append-only) ──▶ verification ──▶ scripts/verify_evidence.py
   └──────────── Next.js + React Flow (frontend/) ◀── verified exports only
```

## Core (`backend/necroshield/`, standard library only)
| Module | Responsibility |
|---|---|
| `contracts.py` | Frozen `ToolCall`, `Decision`, `DispatchRecord`, `Outcome`. Exact-`str` arguments, identifier-shaped names, no control characters, size limits. Canonical JSON (`sort_keys`, compact, `allow_nan=False`). |
| `scenarios.py` | `Grant`, `Policy`, `Check`, `Scenario`. Immutable (`MappingProxyType`, tuples) and validated at construction; an invalid definition raises (fail closed). Digests cover the full manifest. |
| `catalog.py` | The seven scenarios (six attack classes and one control). |
| `tools.py` | Six synthetic tools with explicit argument specs. Over-limit output is an error, never a truncation. `_invoke` is private. |
| `policy.py` | Pure default-deny evaluation. A call is allowed only if a grant for its tool lists every argument it uses and every scoped argument is present with an allowed value. |
| `gateway.py` | The only caller of `tools._invoke`, enforced by an AST test. Decides first; a denied call never reaches tool code. |
| `agent.py` | Naive fixture agent: follows its plan and obeys `assistant: call tool({...})` lines in any tool output. Plans once against a disposable environment. Placeholders bind at execution time from each run's own observations. |
| `runner.py` | Paired runs from fresh state, hash-chained evidence, and `decisive_denials` (exact single-decision counterfactuals). |
| `evaluator.py` | Outcome from observable state only: sink contents, reads, memory, reports. |
| `evidence.py` | Redaction (before hashing), hash chain, no floats in hashed events. |
| `metrics.py` | Benchmark summary computed only from exports, with explicit numerators and denominators. |
| `storage.py` | SQLite history. Triggers block update, delete, and replace through the store. Every read re-verifies the export. |
| `verification.py` | Loads the standalone verifier so the app checks its own evidence with third-party code. |

## Service layer
- `api/app.py`: FastAPI routes for scenarios, runs, exports, verification, benchmark and bundle, MCP replay, and live-track status and runs. The app also serves the static frontend.
- `api/schemas.py`: strict Pydantic models (`extra="forbid"`). They are converted into core types, which validate again.
- `api/guards.py`: ASGI middleware for body limit (256 KB, streamed), origin allowlist on writes, per-client rate limits, and security headers (CSP, nosniff, frame-deny).
- `mcp_server.py`: a `FastMCP` server per sandbox (official SDK). Each tool handler calls the gateway. `replay_over_mcp` drives the fixture intents through a real `ClientSession` on the SDK's in-memory transport.
- `live.py`: a multi-turn tool loop against any OpenAI-compatible endpoint. It is configured only by environment and accepts only HTTPS hosts on an allowlist. Turn, call, and time budgets are enforced, and usage and cost are recorded when pricing is set. If no provider is configured, the track reports itself unavailable.

## Frontend (`frontend/`)
Next.js 15 (App Router, static export), React 19, and `@xyflow/react` 12, with plain CSS design tokens. Pages: Dashboard, Attack Arena, Execution Graph, Replay Lab, Policy Inspector, Evidence Explorer, and Benchmark Studio. Every number comes from an API response. Pages withhold security conclusions when verification fails, and they warn when a run's scenario digest differs from the current definition.

## Two evaluation tracks
| | Deterministic Intent Replay | Live Agent Evaluation |
|---|---|---|
| Decisions | Fixture state machine | A real model's tool calls |
| Pairing | Identical intents in baseline and protected | Independent runs; no call-by-call pairing |
| Evidence | `necroshield.pair/2` | `necroshield.live/1` |
| Claims supported | What the policy does to a fixed attack | How one configured model behaved in those runs |

## Decisions and tradeoffs
- **Typed state machine over LangGraph** for the fixture. Determinism and replay come without a graph runtime. The live track has its own loop.
- **In-process default-deny over OPA/Rego.** There is no second runtime, the rules are cross-checked against the verifier's independent reimplementation (3000 generated calls), and the policy JSON is simple to translate later.
- **SQLite over PostgreSQL for the deployed demo.** The demo is one instance with an append-only evidence log that is verified on read, and SQLite removes a managed database from the judge path. The tradeoff: no horizontal scaling and no concurrent writers across instances. A PostgreSQL adapter is not implemented.
- **Static export served by FastAPI.** One container, same-origin API calls, and no Node runtime in production.
- **No Redis or queue.** A pair runs in about a millisecond, so no queue is needed.
