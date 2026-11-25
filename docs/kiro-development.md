# Kiro development report

This report records only what happened. Every claim links to a file, a commit, or a command result. If a Kiro feature is not listed as used, it was not used.

## Kiro products and features used
| Feature | Used? | Detail |
|---|---|---|
| Kiro Web (Vibe mode, model selection "Auto") | Yes | Every session for this project ran in Kiro Web, in a Linux sandbox. |
| Specs | Yes | `.kiro/specs/phase1-vertical-slice/` and `.kiro/specs/web-platform/`: requirements, design (with traceability to code and tests), and tasks. |
| Steering | Yes | `.kiro/steering/`: `product.md`, `tech.md`, `security.md` (always included) and `testing.md` (fileMatch). These were injected into the agent's context during the sessions. |
| Hooks | Configured; execution not observed | `.kiro/hooks/backend-tests-on-save.json` (PostFileSave → pytest). I ran its command by hand (`31 passed` at the time), but saw no hook output during the sessions. I do not claim that it executed automatically. |
| Subagents | Yes | The `semantic_reviewer` subagent ran two independent reviews (below). No other subagents or custom agents were used. |
| Kiro Crew | No | Not used. No Kiro Crew app exists, so no Kiro Crew bonus is claimed. |
| Powers | No | None loaded. |
| MCP during development | No | No MCP server was connected to Kiro for development. The project's own MCP sandbox (`necroshield.mcp_server`) is product code, tested in CI. It was never attached to Kiro. |
| Learnings | Yes | A user preference was saved: commit as the participant, use simple names, push after changes. |

## How Kiro shaped the work
- **Spec-first slicing.** The phase 1 spec limited the first build to one scenario and set requirements R1 to R5. Every later task traces to a requirement, and the design docs map each requirement to the code and tests that cover it.
- **Steering as guardrails.** `security.md` set four rules: default-deny before dispatch, redact before hashing, synthetic data only, and stating integrity limits. `testing.md` required exact pass/fail/skip reporting and Hypothesis properties. Both rules shaped what was built: the gateway choke point and its AST test, the verify-on-read store, and the "skipped stays skipped" CI gate.
- **Environment constraints drove decisions.** The sandbox has no package index (`INTEGRATIONS_ONLY`). So the core was written with the standard library only, and GitHub Actions became the test bed for FastAPI, the MCP SDK, Next.js, and Playwright. CI also resolved and audited the pinned versions, which were then committed as `backend/constraints.txt` and `frontend/package-lock.json`.

## Independent reviews (semantic_reviewer subagent)
### Review 1: phase 1 core
Confirmed defects:
- Secrets in exported intents and outcomes reached SQLite.
- A forged allow decision with recomputed hashes still verified.
- Emptied intents verified, and header fields were unbound.
- Malformed input crashed the verifier.
- `task_completed` could be a false positive.
- `INSERT OR REPLACE` bypassed the append-only triggers.
- Three tests passed for the wrong reason.

All were fixed with regression tests. Result: 31 → 61 tests passing. Details are in `evidence/phase1-report.md`.

### Review 2: hardening, API, MCP, live track, frontend (`8f39d51..HEAD`)
Verdict: needs changes. 28 findings. Highlights:
- The verifier did not re-derive outcomes or bound arguments (V1).
- Scenario kind and checks were not bound to the digest (V2).
- Pins were ignored for bundles (V3).
- A lone surrogate crashed the verifier (V6).
- `--forwarded-allow-ips='*'` made rate limits spoofable (A1).
- One bad stored row broke the list endpoints (A3).
- Malformed provider JSON crashed the live loop (L1).
- Injected lines were never highlighted (F1).
- The live option could not launch (F2).
- Verification claims in the UI were too broad (F3).

Fixed findings and their tests are listed in `evidence/final-verification.md`. Each fix has a test in `backend/tests/test_review_regressions.py`, `test_api.py`, or `test_live.py`.

## Measurable results
| Point | Tests | Where |
|---|---|---|
| Phase 1 first build | 31 passed | sandbox |
| After review 1 | 61 passed | sandbox |
| Core hardening and six scenarios | 111 passed, 1 skipped (Hypothesis not installed) | sandbox |
| Full backend with API, MCP, live, Hypothesis | 143 passed, 0 skipped | CI run for `5482aa6`, `f584841`, and `8a682ca` |
| After review 2 fixes | 135 passed + 4 skipped locally; 178 passed, 0 skipped in CI; Playwright 18 passed | sandbox; CI for `17eb3f0` and `dca45a5` |

## Session log
### 2026-11-24, session 1 (Kiro Web)
- Researched the Kiro hook and steering formats on kiro.dev. The Devpost rules pages returned 403.
- Wrote steering, the ADR, and the phase 1 spec. Built the stdlib core, verifier, and tests.
- Ran review 1 and fixed its findings.
- Publishing: the sandbox could not create repositories (403), so the participant created `leninathikam/necroshield` and the commits were pushed. At the participant's request, the history was rewritten to the participant's identity with simple messages.

### 2026-11-24, session 2 (Kiro Web)
- Audited the core and rewrote it:
  - immutable, validated definitions;
  - a gateway choke point;
  - no truncation;
  - late-bound intents;
  - six attack scenarios and a control.
- Added the FastAPI service, the MCP sandbox (official SDK), the live-agent track, benchmark bundles, the Next.js app, Playwright tests, CI, and the container.
- CI caught these problems, all fixed:
  - vulnerable dependency pins (pip-audit);
  - a Pydantic incompatibility;
  - a Hypothesis strategy bug;
  - a pipe hiding pytest failures;
  - a vulnerable PostCSS in Next 15 (npm audit; fixed with an override);
  - a synthetic canary flagged by gitleaks (allowlisted narrowly);
  - a mobile layout overlap (Playwright on a Pixel 7 profile).
- Ran review 2 and fixed its findings.

---

# NecroShield 2.0 session (2026-11-24, Kiro Web)

## What was used, and what was not
| Feature | Used? | Evidence |
|---|---|---|
| Specs | Yes | `.kiro/specs/necroshield-2/` (requirements R15 to R23, design, tasks with status notes). Work followed it, and the notes record where it changed. |
| Steering | Yes | `product.md`, `tech.md`, `security.md`, `testing.md` were in context (the exact-counts rule shaped every report). `.kiro/steering/evaluation.md` was written **after** the review of the evaluation; it did not exist while the first optimizer was written. |
| Subagent (`semantic_reviewer`) | Yes | One independent review of 2.0 (20 findings) and the two earlier reviews. No other subagent or custom agent. |
| Hooks | Configured; execution **still not observed** | `.kiro/hooks/backend-tests-on-save.json` exists; no hook output appeared in any session. Not claimed as run. |
| Kiro Crew, Powers, MCP during development | No | Not used. The sandbox's MCP server is product code, never attached to Kiro. |

## What the review changed (measurable)
- The headline held-out comparison was reframed after the reviewer showed it was not a generalisation test. The Lab now leads with a held-out finding: the suggested policy fails one held-out attack.
- Test counts in CI: 143 (before the earlier audit) → 198 → 281 → 393 passed, 0 skipped. Playwright: 18 → 20 → 34.
- Defects the review found and CI confirmed or the reviewer proved with probes: forgeable patch re-check, nine unnoticed MCP drift classes, small-order Ed25519 keys, ignored digest flags. Each has a regression test.

## What spec-driven development did and did not do
It forced requirement-level statements before code (for example R16.2, the mandatory constraint, and R17.1, held-out selection). It did **not** prevent the two process errors the review found: adding the transfer objective after seeing a held-out number, and mislabeling per-task held-out results. Those came from the evaluator's own design, which the spec had not constrained. The new steering file exists because of that.

## Honest accounting of defects
Found by me while building: undercounted false positives (bound-value matching), the evolution first selecting an overfitting patch.
Found by CI: the approval stage never rendering, `ManifestDrift` surfacing as a 500, a stale verifier in CI because of incomplete staging.
Found by the independent review: everything in `evidence/final-verification.md` under the 2.0 table.
