---
inclusion: fileMatch
fileMatchPattern: ["backend/**/*.py", "frontend/**/*.ts", "frontend/**/*.tsx"]
---

# Testing

Maintain pytest unit/integration tests, Hypothesis authorization invariants, official MCP SDK interoperability tests, and Playwright browser workflows. Prefer effect-level assertions over implementation mirrors.

Phase 1 must pass a real API round trip for document injection before expanding scenarios. Assert baseline compromise, protected non-dispatch, and legitimate task completion. Subsequent gates cover provenance/export, deterministic paired replay and benign controls, broader scenarios and UI, then independent review and deployment.

Use a temporary database for automated tests. Verify isolation between runs, stable input digests, unknown input rejection, and evidence mutation detection. A security benchmark must include benign controls for false positives.

Stochastic LLM evaluation is a separate future suite requiring provider/model/seed/repetition metadata. Do not infer its outcome from fixtures.
