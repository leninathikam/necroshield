---
inclusion: fileMatch
fileMatchPattern: ["**/tests/**", "**/*.test.*", "**/*.spec.*"]
---
# Testing

- Every behavior change gets a focused pytest test. Policy, redaction, and hash-chain logic also get Hypothesis property tests.
- Required properties: denied calls never dispatch, baseline and protected runs get identical intended actions, tampered evidence fails verification.
- UI workflows are tested with Playwright against the real API, not mocked responses.
- Deterministic fixture tests and stochastic LLM evaluations stay in separate suites.
- Report exact pass/fail/skip counts. A skipped gate stays labeled skipped.
