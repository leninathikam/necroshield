# ADR 0001: A bounded arena with a deterministic reference agent

Date: 2026-10-30. Status: accepted for the local fixture release.

## Context

An empty repository was inspected after the competition's opening time. The
application must demonstrate a meaningful security boundary before introducing
model credentials, arbitrary tools, or deployment. A blocked instruction is not
evidence of a blocked effect; the gateway must mediate the actual dispatch.

## Decision

Use Next.js with TypeScript, Tailwind, and React Flow for the command center.
Use FastAPI and Pydantic for the API and typed contracts. Persist immutable run
identities and trace snapshots through SQLAlchemy, with an Alembic migration.
PostgreSQL is the deployment database; SQLite is the explicitly identified local
alternative when no database service is available.

Choose a small typed state machine over LangGraph for this release. The fixed
fixture protocol has bounded states, no model calls, no dynamic planning, and no
need for graph checkpoint infrastructure. Introducing LangGraph now would add a
second graph vocabulary and nondeterminism without exercising either benefit.
Reconsider it when a separately evaluated model adapter needs durable branching.

Choose a pure, default-deny Python authorization function over OPA/Rego. This is
the documented equivalent, not an OPA integration. Exact tool and argument
allowlists derive from trusted task capabilities; untrusted content cannot grant
permissions. Authorization happens immediately before dispatch and denial leaves
tool state untouched. Property tests exercise malformed and unknown requests.

Keep attack tools inert: synthetic documents, synthetic records, run-local memory,
and a run-local sink. An exfiltration result is a write to a Python fixture sink,
never an outbound network request. No shell, arbitrary filesystem paths, imported
plugins, freeform URLs, or production credentials enter the execution interface.

Replay compares identical fixture intentions and reset initial state, changing
only enforcement. Call it `deterministic_intent_replay`. It measures gateway
effects and task utility for the reference agent; it does not claim that a real
LLM would make the same decisions after different tool feedback. Store scenario
versions, policy versions, trace provenance, and independent run IDs.

Measure success from actual synthetic side effects and task output. Keep cost
unknown (`null`) because there is no metered provider. Timings are measured local
execution observations. Separate benign controls from attacks in aggregate rates.

No Redis yet. Bounded synchronous jobs are sufficient for a local, finite fixture
suite; a broker becomes justified by cancellation, sustained concurrency, or
remote model latency. Retain execution timeouts and a concurrency budget.

## Consequences

The result is reproducible without credentials and can falsify denial and utility
claims. It cannot estimate LLM vulnerability rates or establish a universal sandbox.
PostgreSQL, Kiro runtime behavior, deployment, and outside testing need their own
evidence. Hash chains detect changes relative to a retained digest, not malicious
rewrites by an administrator who controls both data and the digest.

## Delivery gates

1. One attack: API, persistence, dispatch denial, legitimate result, and UI wiring.
2. Policy adversarial inputs, ordered forensic events, redacted evidence.
3. Paired replay invariants, effect evaluator, benchmark controls.
4. Broader fixtures and accessible completed/error/empty dashboard states.
5. Independent review, database integration, deployment and external testing.

Each gate needs executed tests. The evidence report distinguishes passing gates
from prerequisites that cannot be exercised in this environment.
