# Kiro development log

Every entry records work actually done in a Kiro session, along with the commands run and the observed results.

## 2026-11-24, Kiro Web (Vibe mode, model "Auto")
**Research**
- Read the Kiro docs for steering (front matter, inclusion modes) and hooks (`.kiro/hooks/*.json`, `version: "v1"`).
- The Devpost pages for rules, FAQ, and landing returned HTTP 403 to automated fetches. A search snippet confirmed the October 30 to December 4, 2026 window. See `docs/hackathon-compliance.md`.

**Environment findings**
- The sandbox network mode was `INTEGRATIONS_ONLY`, so `pip install fastapi ...` failed with a proxy 403. Kiro chose to build a framework-free core first (ADR 0001).
- GitHub: `git push` and `gh api` calls returned 404 for `leninathikam/necroshield`, and `POST user/repos` returned 403. Nothing was published from this session.

**Files written**
- `.kiro/steering/`: `product.md`, `tech.md`, `security.md` (always included) and `testing.md` (fileMatch on test files).
- `.kiro/specs/phase1-vertical-slice/`: requirements (R1 to R5, EARS-style), design with a module-to-requirement table, and a task list.
- `.kiro/hooks/backend-tests-on-save.json`: a PostFileSave hook that runs pytest. The command was exercised manually and printed `31 passed`. It activates automatically on the next session start.
- `backend/necroshield/`: the core modules and `__main__` CLI.
- `scripts/verify_evidence.py`, `backend/tests/` (31 tests), and `evidence/phase1-report.md`.

**Results**
- `python3 -m pytest -rA`: 31 passed, 0 failed, 0 skipped.
- CLI pair: baseline leaked the canary, protected denied `send_message` before dispatch, and both runs completed the report. The standalone verifier printed `OK ... (10 events)`.

**Not done in this session**
- No subagent review yet, no MCP inspector, no UI.
