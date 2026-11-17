---
inclusion: always
---

# Architecture

Use Next.js, TypeScript, Tailwind, and React Flow in `frontend/`; FastAPI, Pydantic, and SQLAlchemy in `backend/`. PostgreSQL is the deployment database. SQLite is an explicit local fallback, never evidence of PostgreSQL integration passing.

Keep scenario registry, typed intents, policy decisions, tool effects, evaluator, tracing, and persistence in cohesive modules. The gateway authorizes before dispatch; a denied call must never reach a tool handler. UI views consume persisted API results.

Use a bounded typed state machine before adding an orchestration framework. Add Redis and isolated job workers only when asynchronous workloads justify them. Scenario definitions and policy versions are part of provenance.

Paired fixture runs use independent world state and identical intent plans. Describe this as deterministic intent replay, not adaptive model counterfactual replay. Preserve UUID run identity and append-only event sequencing. A hash chain detects alteration relative to a trusted digest; it does not make the database immutable.

The only MCP execution targets are inert mock tools. The development MCP inspector is read-only and separate from execution capabilities.
