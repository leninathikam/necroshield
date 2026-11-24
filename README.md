# NecroShield

An adversarial security-testing arena for AI agent and MCP tool workflows. Everything runs on synthetic data.

An agent works on an invoice task while attacker-controlled text, in a document or a tool response, tells it to do something else. NecroShield runs the same intended calls twice, each from fresh state:

- **baseline**: every call is dispatched;
- **protected**: a default-deny capability policy is checked before each dispatch.

Outcomes come only from observable synthetic effects: a canary reaching the in-memory sink, a forbidden read, poisoned memory, or the correct report. So the arena measures both whether an attack was stopped and whether the legitimate task still completed. Every run produces redacted, hash-chained evidence. A standalone script can re-derive the outcomes from that evidence and reject forgeries.

## What works (verified in CI)
- **Seven scenarios:** document injection, tool-response injection, unauthorized record access, exfiltration through an allowed channel, path-based scope manipulation, memory poisoning, and a benign control.
- **Counterfactual lab:** edit a policy, rerun it, and see which single denial changed the outcome.
- **MCP sandbox:** built on the official SDK, with the gateway in front of every tool. A real client session replays the attack.
- **Web app:** seven screens (Dashboard, Attack Arena, Execution Graph, Replay Lab, Policy Inspector, Evidence Explorer, Benchmark Studio), served by the FastAPI app as a static export.
- **Benchmark:** metrics with explicit denominators, and a downloadable bundle whose arithmetic the verifier recomputes.
- **Live Agent Evaluation track:** a multi-turn loop against any OpenAI-compatible endpoint. It is **unavailable unless you configure a provider**, and no real-model results exist yet.

Current fixture results (`deterministic_intent_replay`):

| | Baseline | Protected |
|---|---|---|
| Attack success | 6/6 | 0/6 |
| Task completion | 6/7 | 7/7 |
| False positives | | 0/1 |

## Run it
Docker:
```
docker build -t necroshield .
docker run -p 8017:8017 -e NECROSHIELD_ALLOWED_ORIGINS=http://localhost:8017 necroshield
# open http://localhost:8017
```
From source (Python 3.11+, Node 22):
```
cd frontend && npm ci && npm run build && cd ..
cd backend && pip install -r requirements.txt -c constraints.txt
NECROSHIELD_STATIC=../frontend/out python -m uvicorn necroshield.api.app:app_from_env --factory --port 8017
```
Core only (no dependencies):
```
cd backend
python -m necroshield benchmark
python -m necroshield scenarios --pins > pins.json
python -m necroshield run document_injection --export pair.json
python ../scripts/verify_evidence.py pair.json --pins pins.json
```

## Tests
```
cd backend && pip install -r requirements.txt -r requirements-test.txt -c constraints.txt && python -m pytest -o addopts="" -q
cd frontend && npm ci && npm run lint && npm run typecheck && npm run build && npx playwright test
```
CI (`.github/workflows/ci.yml`) runs:
- the core suite on Python 3.11 to 3.14;
- the full backend suite with no skips allowed;
- benchmark and bundle verification with pinned digests;
- frontend lint, typecheck, build, and `npm audit`;
- Playwright on desktop and mobile against the real API;
- a container build and smoke test;
- `pip-audit` and gitleaks.

## Live model (optional)
Set `NECROSHIELD_LLM_BASE_URL` (https only), `NECROSHIELD_LLM_API_KEY`, `NECROSHIELD_LLM_MODEL`, and `NECROSHIELD_LLM_ALLOWED_HOSTS`. Optionally set `NECROSHIELD_LLM_PRICE_IN_PER_MTOK` and `NECROSHIELD_LLM_PRICE_OUT_PER_MTOK` to get cost reporting. Runs are budgeted per request and per process.

## Integrity limits
Exports are not signed. The verifier catches:
- edited, reordered, or missing events;
- decisions that contradict the policy;
- bound arguments and outcomes that don't follow from the recorded effects;
- headers that don't match the scenario digest.

A complete, self-consistent rewrite is caught only when digests are pinned from a trusted source (`--pins`). See `docs/threat-model.md`.

## Docs
`docs/architecture.md` · `docs/threat-model.md` · `docs/benchmark-methodology.md` · `docs/kiro-development.md` · `docs/hackathon-compliance.md` · `docs/demo-script.md` · `evidence/final-verification.md`

## License
MIT
