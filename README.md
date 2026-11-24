# NecroShield

An adversarial security-testing arena for AI agent and MCP tool workflows. It runs only against synthetic environments.

A fixture agent reads an untrusted document and proposes tool calls. NecroShield replays those exact calls twice, each from fresh state:

- **baseline**: every call is dispatched;
- **protected**: a default-deny capability policy is checked before each dispatch.

Outcomes come from observable synthetic effects (a canary reaching an in-memory sink, the invoice values appearing in the report), so the arena measures both attack success and legitimate task completion. Every run produces a redacted, hash-linked event chain that a standalone script can verify.

## Status
Phase 1 (vertical slice, one scenario) works and is tested. See [evidence/phase1-report.md](evidence/phase1-report.md). The API, database migrations, dashboard, and MCP server are not built yet.

## Run it
Requires Python 3.11+. The core has no third-party dependencies; tests need pytest.
```
cd backend
python3 -m pytest
python3 -m necroshield run document_injection --export pair.json
python3 ../scripts/verify_evidence.py pair.json
```

## Layout
- `backend/necroshield/`: contracts, scenarios, mock tools, policy gateway, fixture agent, runner, evaluator, evidence, storage
- `scripts/verify_evidence.py`: verifier that imports no application code
- `.kiro/`: steering, specs, and hooks used to build this project
- `docs/adr/`: architecture decisions

## Integrity limits
The hash chain detects edited, reordered, inserted, or removed events. The verifier also rejects internally inconsistent exports, such as a denied call marked as dispatched, even after the hashes are recomputed. It cannot detect a full, self-consistent forgery, because exports are not signed.

## License
MIT
