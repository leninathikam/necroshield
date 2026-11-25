# Tasks: NecroShield 2.0

- [x] 1. Red Team variants (seeded, approved axes) with tests
  - _Requirements: R15.1, R17.3_
- [x] 2. Corpus expansion: new attack bases, at least 10 benign controls, development and held-out split
  - _Requirements: R17.1, R17.4_
- [x] 3. Blue Team strategies and legitimate-trace extraction
  - _Requirements: R15.2, R15.4_
- [x] 4. Evaluator: scoring, mandatory constraint, Pareto frontier, held-out report, four-arm benchmark
  - _Requirements: R15.3, R16, R17.2_
- [x] 5. API endpoints (bounded, cached) and CLI `evolve`
  - _Requirements: R16.4, R23.2_
- [x] 6. Attack Theatre UI with Pareto chart and approve-and-run
  - _Requirements: R22_
- [x] 7. Patch compiler and download
  - _Requirements: R18_
- [x] 8. Signed bundles and pure-Python verification
  - _Requirements: R21_
- [ ] 9. MCP trust inspector
  - _Requirements: R20_
- [ ] 10. Information-flow labels and destination constraints
  - _Requirements: R19_
- [ ] 11. Memory measurement in CI, independent review, docs, final report
  - _Requirements: R23.1_

## Status notes
- Tasks 1–6 are implemented and tested (core: 212 passed locally; API and browser tests run in CI).
- Finding recorded during task 4: the cheapest candidate, `violation_patch`, passes its own scenario but stops 0 of 4 sibling attacks on held-out scenarios. Cross-attack transfer was added to the objectives because of it. Selection moved from `violation_patch` to `scoped_trace`.
- Finding recorded during task 4: the first false-positive count matched legitimate calls by bound value, which undercounted after a denial changed later bindings (28/40 instead of 40/40 for `deny_all`). Calls are now matched by plan template.
- CI caught a defect in task 6: the stage reveal stopped one stage short, so the approval step never rendered. Fixed with the browser test that found it.
