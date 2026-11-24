---
inclusion: always
---
# Technology and code quality

- Frontend: Next.js, TypeScript, Tailwind, React Flow.
- Backend: Python, FastAPI, Pydantic, SQLAlchemy, Alembic. PostgreSQL for deployment, SQLite for local runs.
- Agent execution: a bounded, typed state machine (see docs/adr/0001-architecture.md).
- MCP: the official SDK with sandboxed mock tools.
- Tests: pytest, Hypothesis, Playwright.
- Prefer small cohesive modules, explicit Pydantic contracts, and typed boundaries. No placeholder endpoints, hardcoded success values, or simulated responses presented as live results.
- Add a dependency only with a stated reason in the ADR or PR.
- Never claim a feature works until its tests have run. Record exact pass/fail/skip results.
