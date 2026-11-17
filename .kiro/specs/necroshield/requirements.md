# NecroShield requirements

Initial specification dated October 30, 2026. The development log records acceptance evidence and identifies any work performed in Kiro.

## R1 — Scoped vertical execution

As an investigator, I want a bounded document-injection experiment that produces observable evidence.

1. WHEN an investigator selects a registered scenario, THE arena SHALL validate its identifier and execute only its versioned synthetic records and fixed tool intents.
2. IF the scenario identifier is unknown or request fields are invalid, THE API SHALL reject the request without executing a tool.
3. THE arena SHALL expose no arbitrary command, public target, or user-controlled network destination.

Acceptance: one API-created document scenario persists paired run IDs, an observable compromised baseline, a protected blocked effect, and a completed legitimate task.

## R2 — Authorization before execution

As a policy author, I want deterministic fail-closed enforcement independent of agent text.

1. WHEN protected execution proposes a tool call, THE gateway SHALL validate trusted scope, exact tool, resource, and arguments before invoking its handler.
2. IF authorization fails, THE gateway SHALL emit a denial and SHALL NOT invoke the handler.
3. IF a tool or argument schema is unknown, THE gateway SHALL deny the request.

Acceptance: unit tests and generated invalid requests prove non-dispatch; legitimate read/report actions remain executable.

## R3 — Evidence provenance and export

As an investigator, I want to verify the sequence and safely share a report.

1. WHEN a run emits an event, THE tracer SHALL record its sequence, timestamp, action, policy decision, reason, and chained digest.
2. WHEN evidence is exported, THE exporter SHALL recursively redact sensitive material and identify the export's provenance and redaction semantics.
3. IF an event changes, THE verifier SHALL reject the altered chain.

Acceptance: persisted round trip, hash mutation test, recursive redaction test, and export endpoint verification.

## R4 — Replay semantics and utility

As an evaluator, I want a fair comparison with explicit limits.

1. WHEN a pair is created, THE arena SHALL execute the same deterministic intent plan in independent baseline and protected worlds.
2. THE response SHALL label replay as `deterministic_intent_replay` and SHALL NOT claim adaptive model equivalence.
3. WHEN evaluating outcomes, THE evaluator SHALL derive attack success from effects and task completion from the legitimate output state.
4. THE benchmark SHALL report attack success, blocked executions, false positives, task completion, measured latency, tool calls, and unavailable model cost distinctly.

Acceptance: identical intent provenance across the pair; a benign control completes without a denial; aggregate denominators exclude benign cases from attack-success rates.

## R5 — Registry breadth

As a researcher, I want reproducible coverage of six threat classes.

1. AFTER Phase 1 passes, THE registry SHALL include document injection, tool-output injection, unauthorized tool use, synthetic exfiltration into an in-memory sink, privilege-boundary violation, and memory poisoning, plus a benign control.
2. THE registry SHALL publish versions, tasks, threat categories, scope, and deterministic evaluator definitions.

Acceptance: each registered case runs through the public API and effect-level tests.

## R6 — Usable command center

As an investigator, I want to inspect paired runs and errors accessibly.

1. WHEN no run exists, THE dashboard SHALL show an honest empty state and scenario selection.
2. WHEN a run is selected, THE dashboard SHALL show its actual graph, timeline, metrics, policy details, history, and evidence export.
3. IF the backend or run fails, THE dashboard SHALL show a recoverable error rather than substitute fixture metrics.
4. THE dashboard SHALL support keyboard navigation, readable contrast, responsive layouts, and text equivalents of graph decisions.

Acceptance: Playwright creates a run, inspects a denial, reloads durable history, downloads evidence, and covers unavailable-backend handling.

## R7 — Durable contracts

As an operator, I want validated storage and repeatable setup.

1. THE API SHALL persist runs with a migrated relational schema and immutable UUID identity.
2. THE application SHALL support PostgreSQL deployment and an explicitly labeled SQLite local alternative.
3. THE API SHALL bound request size/work, reject malformed input, and log structured execution metadata without secret bodies.

Acceptance: migrations execute against the database being claimed; restart preserves history; invalid requests produce bounded 4xx errors.

## R8 — Honest Kiro and delivery evidence

As a hackathon entrant, I want auditable tool use and original work.

1. THE repository SHALL retain its root `.kiro` specs, steering, hooks, agents, and MCP configuration.
2. WHEN a development contribution is recorded, THE log SHALL identify whether Kiro performed the work and reference concrete output or a commit.
3. IF Kiro, hosting, or credentials are unavailable, THE delivery report SHALL identify that blocker and SHALL NOT claim the corresponding gate passed.

Acceptance: configuration contract validation; actual Kiro validation/execution recorded separately; public repository/app/video verified before submission.
