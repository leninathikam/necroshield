# Independent security and correctness review

A separate review agent examined the backend implementation on October 30, 2026. The review covered authorization, fixture planning, outcome evaluation, redaction, event provenance, worker isolation, persistence, API ingress, the MCP server, startup, CI, and the standalone evidence verifier.

Conclusion: no unresolved actionable defect was identified in the reviewed bounded synthetic workflow after the fixes below. This is a source review with targeted executable regressions, not an independent assessment of arbitrary agents or a public service.

## Findings resolved

- **P2 — Cross-origin local side effects and unbounded request parsing.** A browser's simple POST could start a benchmark even when CORS prevented reading the response. `backend/necroshield/http_boundary.py` now rejects unapproved mutating-request Origins before execution, rejects malformed Content-Length, and enforces a 4 KiB body budget for both known-length and chunked bodies. Accepted defaults use this application's ports 3017/8017; the unrelated application on port 3000 is rejected. Origin-less CLI requests remain supported.
- **P2 — Credential aliases in denied-call evidence.** Unknown arguments were correctly denied, but standard names such as `access_token`, `client_secret`, and `apiKey` could remain in the denial trace. `backend/necroshield/evidence.py` normalizes sensitive key names and redacts recognized aliases and suffixes recursively before hashing. Tests use inert synthetic values at both top level and inside nested lists/dictionaries.
- **P2 — Contradictory evidence accepted by the independent verifier.** A correctly rehashed protected trace containing `bypass`, or top-level effects disagreeing with the completion event, could pass consistency verification. `scripts/verify_evidence.py` now enforces mode-specific decisions and equality of recorded effects. Regression exports are deliberately rehashed so rejection proves semantic checking, not merely checksum validation.
- **P2 — Untraced planning dispatch.** The fixture planner performed an extra document tool read outside the gateway. No unauthorized effect occurred because the read was a fixed permitted fixture, but it contradicted the dispatch invariant and omitted the planning read from run evidence. `Scenario.document_response()` now materializes pure immutable fixture data; actual tool calls occur only through the traced gateway. A regression fails if planning invokes any tool handler.
- **P3 — Read-only inspection created missing stores.** Inspector calls used the normal repository initializer, which could create directories, tables, and an empty database when the intended store was missing. Both inspector calls now use `Repository(read_only=True)`: missing SQLite files fail clearly without creating paths, existing SQLite connections use native URI `mode=ro`, and application writes are rejected. Tests verify existing evidence remains readable and even direct SQL deletion fails. PostgreSQL read-only transactions are configured, with their execution left to the opt-in PostgreSQL acceptance test.

## Executed evidence

The reviewer ran these checks against actual application code:

- `test_independent_review.py` plus `test_independent_verifier.py`: **15 passed**, 7.73 seconds, after the port and planner fixes. This covers ingress rejection/non-dispatch, legitimate local clients, real export verification, and rehashed semantic contradictions.
- Focused credential-alias regressions: **8 passed**, 6.65 seconds, after the redaction fix.
- `python .kiro/scripts/focused_checks.py backend`: **passed**, exit 0; selected 28 policy, vertical-slice, and independent boundary cases, using the installed project environment and a fresh workspace test directory. This was a manual command invocation, not a Kiro event.
- `python .kiro/scripts/focused_checks.py frontend`: **passed**, exit 0; TypeScript contracts checked after the production build stabilized. This was also a manual invocation, not a Kiro event.
- `python .kiro/scripts/validate_config.py`: **passed**, exit 0; checks this project's documented hook/agent/MCP/steering/spec subset, not an official Kiro runtime schema.

The backend implementer additionally reported **39 passed, 1 PostgreSQL test skipped** before the final focused changes, then **33 focused tests passed** covering migrations, the final independent boundary tests, configuration, and engine behavior. After the read-only inspector fix, **6 focused tests passed** in 11.82 seconds: three inspector regressions, real SDK stdio interoperability, migration, and the worker-backed Phase 1 API test. The reviewer independently inspected the final read-only implementation and test assertions. Official MCP `ClientSession` interoperability and the API benchmark exercised real local processes and persisted results. Final combined release counts supersede these incremental checks; they are not added together because suites overlap.

The first restricted-sandbox test attempt failed while creating pytest's default temporary directory, before application code ran. Verification used workspace-local temporary directories and approved execution outside that restriction. One frontend hook attempt overlapped Next.js output regeneration and reported missing generated type files; the stable rerun passed as recorded above.

## Confirmed boundaries and limits

Protected calls use exact typed capabilities/resources/arguments before dispatch. Baseline bypass is confined to the inert catalogue. Worlds are fresh per paired run; security outcomes come from changed synthetic state and legitimate output, with separate benign-control measurements. Evidence is redacted before event hashing; hashes provide consistency relative to trusted digests, without authorship or notarization.

Worker time/memory/concurrency limits and disabled Python network operations contain trusted fixture execution. They are not an arbitrary-code isolation guarantee. The HTTP API is a local development service, not a reviewed authenticated multi-user deployment.

Kiro runtime work remains pending. The subsequent November 16 release run passed the PostgreSQL integration test, including a database-enforced write rejection through the inspector. The [release evidence](../evidence/README.md) records the runtime and suite result. Public deployment, external testing, and stochastic model robustness require their own evidence.
