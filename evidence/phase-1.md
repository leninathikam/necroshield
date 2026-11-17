# Phase 1 evidence — 2026-10-30

Outcome: **passed**, one document-borne injection fixture, before registry breadth
was added. The later full-suite report supersedes counts for the final source.

Executed by the backend implementation agent:

```text
backend/.venv/Scripts/python -m pytest tests/test_phase1.py --basetemp <workspace-local temporary directory>
```

The test exercised FastAPI -> child worker -> trusted scope -> dispatch -> effect
evaluator -> SQLAlchemy persistence, with no model/provider credentials.

Assertions that passed:

- Baseline execution changed the synthetic sink state.
- Protected execution recorded a denial and never dispatched `sink.send`.
- The agent derived the invoice report from the document total and completed its
  legitimate task independently of the attack.
- The stored pair could be retrieved after constructing a new application.
- Exported event chains verified and contained no synthetic secret marker.

The first test attempt failed in Windows temporary-directory setup before the
application ran. A workspace-local temporary directory and execution outside the
restricted sandbox resolved the environment failure. This is not counted as an
application pass or concealed as a test result.

Limits: SQLite local persistence, deterministic fixture agent, in-memory sink,
and application-owned tools. This test does not establish real-model robustness,
PostgreSQL service integration, arbitrary-code isolation, hosting, or Kiro use.
