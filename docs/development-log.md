# Development log

Every entry records work actually done in a session, along with the commands run and the observed results.

## 2026-11-24, web sandbox session
**Research**
- Read the docs for steering (front matter, inclusion modes) and hooks (`.kiro/hooks/*.json`, `version: "v1"`).
- The Devpost pages for rules, FAQ, and landing returned HTTP 403 to automated fetches. A search snippet confirmed the October 30 to December 4, 2026 window. See `docs/hackathon-compliance.md`.

**Environment findings**
- The sandbox network mode was `INTEGRATIONS_ONLY`, so `pip install fastapi ...` failed with a proxy 403. Decision: build a framework-free core first (ADR 0001).
- GitHub: the sandbox integration could not create repositories (`POST user/repos` returned 403). The participant deleted the earlier `leninathikam/necroshield` repo and created a new empty one by hand. The commits were then pushed to `main`.

**Files written**
- `.kiro/steering/`: `product.md`, `tech.md`, `security.md` (always included) and `testing.md` (fileMatch on test files).
- `.kiro/specs/phase1-vertical-slice/`: requirements (R1 to R5, EARS-style), design with a module-to-requirement table, and a task list.
- `.kiro/hooks/backend-tests-on-save.json`: a PostFileSave hook that runs pytest. The command was exercised manually and printed `31 passed`. It activates automatically on the next session start.
- `backend/necroshield/`: the core modules and `__main__` CLI.
- `scripts/verify_evidence.py`, `backend/tests/` (31 tests), and `evidence/phase1-report.md`.

**Results**
- `python3 -m pytest -rA`: 31 passed, 0 failed, 0 skipped.
- CLI pair: baseline leaked the canary, protected denied `send_message` before dispatch, and both runs completed the report. The standalone verifier printed `OK ... (10 events)`.

**Independent review**
- Reviewed the phase 1 core commit and ran its own probes. Confirmed defects included unredacted secrets in exported intents, a forged-allow decision that still verified, a storage trigger bypass via `INSERT OR REPLACE`, and vacuous tests. The full list and fixes are in `evidence/phase1-report.md`.
- After the fixes: `python3 -m pytest -rA` gave 61 passed, 0 failed, 0 skipped. Pinned-digest verification of a fresh export printed `OK ... 10 events (digests pinned)`.

**Not done in this session**
- No MCP inspector, no API, no UI (they need packages the sandbox cannot install).
