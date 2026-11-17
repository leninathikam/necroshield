# Implementation tasks

Acceptance-driven phases. Mark a phase complete only after its checks run and its evidence is recorded. Tasks are initially unchecked so code generation cannot imply verification.

- [x] 1. Phase 1 — One working document-injection slice
  - [x] 1.1 Implement versioned document fixture, exact trusted scope, typed intents, and inert tools. _Requirements: R1, R2_
  - [x] 1.2 Implement FastAPI create/read pair endpoints, validation, migrations, and persistence. _Requirements: R1, R7_
  - [x] 1.3 Connect a minimal real-data dashboard with loading, empty, and failure states. _Requirements: R6_
  - [x] 1.4 Run effect-level acceptance tests proving baseline compromise, protected non-dispatch, and task completion; record evidence before breadth expansion. _Requirements: R1, R2_
- [x] 2. Phase 2 — Policy and forensic evidence
  - [x] 2.1 Add generated fail-closed authorization tests and trusted-scope isolation. _Requirements: R2_
  - [x] 2.2 Add event chaining, provenance verification, redacted export, and mutation tests. _Requirements: R3_
  - [x] 2.3 Expose graph/timeline policy reasons and export actual stored evidence. _Requirements: R3, R6_
  - [x] 2.4 Record runnable commands, pass/fail counts, and limitations for this phase. _Requirements: R8_
- [x] 3. Phase 3 — Replay and benchmarks
  - [x] 3.1 Enforce fresh paired worlds and identical versioned intent plans; label replay semantics. _Requirements: R4_
  - [x] 3.2 Add benign control and compute effect-based security/utility metrics with explicit denominators and null provider cost. _Requirements: R4_
  - [x] 3.3 Add benchmark CLI/API and read-only official-SDK MCP result inspector; verify interoperability. _Requirements: R4, R8_
  - [x] 3.4 Run replay, benchmark, and control acceptance checks; record phase evidence. _Requirements: R4, R8_
- [x] 4. Phase 4 — Breadth and interface
  - [x] 4.1 Add tool-output injection, unauthorized use, in-memory sink exfiltration, privilege violation, and memory poisoning. _Requirements: R5_
  - [x] 4.2 Complete real-data React Flow graph, paired comparison, timeline, decision inspector, history, and benchmark view. _Requirements: R6_
  - [x] 4.3 Run scenario matrix, build/typecheck, Playwright real-API workflows, and visual/keyboard checks. _Requirements: R5, R6_
  - [x] 4.4 Record phase evidence and fixture-versus-model limits. _Requirements: R4, R8_
- [ ] 5. Phase 5 — Independent review and submission
  - [x] 5.1 Independently review authorization, evaluator, export, isolation, and public API exposure; fix actionable findings and rerun affected tests. _Requirements: R2, R3, R7_
  - [ ] 5.2 Validate config against actual Kiro; use Kiro for a concrete implementation/review change and preserve its real contribution log. _Requirements: R8_
  - [x] 5.3a Verify PostgreSQL migrations, evidence persistence, and read-only inspection on a real PostgreSQL server. _Requirements: R7_
  - [ ] 5.3b Verify deployment with restricted access, enforced resource/egress policy, and external testing. _Requirements: R7_
  - [ ] 5.4 Recheck rules and personal/team eligibility; provide public GitHub repository, license, working app URL, under-three-minute public YouTube demo, category, and truthful Kiro writeup. _Requirements: R8_

Current Kiro runtime gate: pending; authored configuration is not evidence of Kiro development.

The [release evidence](../../../evidence/README.md) records each phase, the full backend suite with PostgreSQL, the production build, and the browser acceptance checks. The [independent review](../../../docs/security-review.md) records findings and targeted regressions. Genuine Kiro work, external deployment and testing, and submission remain pending.
