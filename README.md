# NecroShield

An adversarial security-testing arena for AI agent and MCP tool workflows. Everything runs on synthetic data.

An agent works on an invoice task while attacker-controlled text, in a document or a tool response, tells it to do something else. NecroShield runs the same intended calls twice, each from fresh state: **baseline** (every call dispatched) and **protected** (a default-deny capability policy checked before each dispatch). Outcomes come only from observable synthetic effects, so the arena measures both whether an attack was stopped and whether the legitimate task still completed. Every run produces redacted, hash-chained evidence that a standalone script can re-verify.

Version 2.0 adds a bounded closed loop on top of that: a Red Team makes seeded variations, a Blue Team proposes structured policy candidates, an independent evaluator scores them, and **a human approves** what runs. The model never edits the enforcement engine and cannot grant itself anything.

## What works (verified in CI)
- **22 scenarios**: 11 attacks in 6 classes and 11 benign controls, split into development (10) and held-out (12) before any synthesis ran.
- **Attack Theatre**: attack, red-team variants, candidate policies, independent evaluation, approval, and a verified outcome, all from backend runs.
- **Policy Lab**: eight policy strategies, exact denominators, a mandatory security constraint, a Pareto frontier, cross-attack transfer, and held-out results with their limits stated.
- **Security patch compiler**: a failure becomes a JSON patch with a regression spec that can be re-checked offline. Nothing is applied automatically.
- **MCP trust inspector**: the sandbox's real `tools/list` is hashed and compared with an approved manifest. Description, schema, tool, and annotation drift are refused until a person approves that exact digest.
- **Optional Ed25519 signed evidence**, verified by the standalone verifier in pure Python. See `docs/evidence-signing.md` for what a signature does and does not prove.
- **MCP sandbox** on the official SDK, with the gateway in front of every tool.
- **Live Agent Evaluation track**: unavailable unless an operator configures a provider, and **no real-model results exist yet**.

## Results (deterministic fixture replay; scenarios v2.0.0 / corpus above)
Original seven scenarios (`python -m necroshield benchmark`): unprotected attack success 6/6, protected 0/6; task completion 6/7 unprotected, 7/7 protected; false positives 0/1; denial rate 6/36.

**Disclosure first.** Held-out results influenced the design of this benchmark. The cross-attack transfer objective was added after a held-out result showed the cheapest patch overfitting, and one held-out attack (`memory_overwrite_allowed_key`) was added after an independent review. Selection still uses development scores only, but the objective set and the corpus were shaped by what held-out data showed. The corpus is small and author-built, and the split is author-chosen. The manual policies were written by the author, who knew the attacks.

Policy evaluation (`python -m necroshield evolve`). The Lab's suggestion uses development scores only. The two kinds of strategy answer different questions and are reported in separate tables.

**Plan-conditioned strategies** (compiled per scenario from that scenario's own trusted plan). Their held-out columns are **not a generalisation test**: they show that a policy built from the right plan works.

| Strategy | Dev: attacks stopped | Dev: tasks | Held-out: attacks stopped | Held-out: tasks |
|---|---|---|---|---|
| allow_all, tool_allowlist | rejected | | | |
| deny_all | 5/5 | 0/10 | 6/6 | 0/12 (blocks everything) |
| **scoped_trace** (suggested by the Lab) | 5/5 | 10/10 | **5/6** | 11/12 |
| exact_trace | 5/5 | 10/10 | 6/6 | 12/12 |
| violation_patch | 5/5 | 10/10 | 6/6 | 12/12 (stops only 1/5 sibling attacks) |

**Development-fitted strategies** (one global policy fitted on development scenarios only). Their held-out columns are the real generalisation evidence, and it is weak.

| Strategy | Dev: attacks stopped | Dev: tasks | Held-out: attacks stopped | Held-out: tasks |
|---|---|---|---|---|
| global_tool_allowlist | rejected | | | |
| global_scoped | 5/5 | 10/10 | 4/6 | 7/12 (4/47 legitimate calls denied) |

Read these honestly:
- The suggested policy **fails one held-out attack** (`memory_overwrite_allowed_key`): it leaves free-text arguments open. The Lab and Attack Theatre report this. In Attack Theatre the candidates are scored after the attack is seen, so what they select there is not a held-out result.
- The hand-written manual policies stop 6/6 held-out attacks and complete 12/12 tasks. That does not show the synthesized policies are worse or better in general: the manual ones were written with knowledge of the attacks, and the synthesized ones were not tuned to this attack.
- These results say nothing about how a language model behaves.

## Not implemented
- **Information-flow tracking and data provenance (spec R19).** The policy pins argument values (including attachments by reference), which constrains some flows, but there is no label propagation. This is not information-flow control.
- **Public deployment**, **real-model runs**, the **demo video**, and corpus growth toward 30 scenarios. See `evidence/final-verification.md`.

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
python -m necroshield benchmark                      # the seven catalog scenarios
python -m necroshield evolve --out evolution.json    # policy strategies over the corpus
python -m necroshield patch data_exfiltration --base violation_patch --base-from tool_response_injection --out patch.json
python -m necroshield check-patch patch.json
python -m necroshield scenarios --pins > pins.json
python -m necroshield run document_injection --export pair.json
python ../scripts/verify_evidence.py pair.json --pins pins.json
```
Signing (needs the `cryptography` package): `python -m necroshield keygen --out key.b64`, then `sign` and `verify_evidence.py --public-key`.

## Tests
```
cd backend && pip install -r requirements.txt -r requirements-test.txt -c constraints.txt && python -m pytest -o addopts="" -q
cd frontend && npm ci && npm run lint && npm run typecheck && npm run build && npx playwright test
```
CI (`.github/workflows/ci.yml`) runs the core suite on Python 3.11 to 3.14, the full backend suite with no skips allowed, benchmark and bundle verification with pinned digests, frontend lint, typecheck, build and `npm audit`, Playwright on desktop and mobile against the real API, a production-conditions container job (assigned PORT, root-owned disk, restart, reset, peak memory under 512 MB), `pip-audit`, and gitleaks.

## Live model (optional, operator-only)
Paid inference is never available to visitors. See `docs/live-evaluation.md` for the budgeted CLI (`python -m necroshield live`, $2 cap by default).

## Integrity limits
The verifier catches edited, reordered, or missing events; decisions that contradict the policy; bound arguments and outcomes that do not follow from the recorded effects; and headers that do not match the scenario digest. Exports are **not signed by default**. A complete, self-consistent rewrite is caught only when digests are pinned from a trusted source, or when a signature from a trusted key is required. A signature proves who vouched for the content, not that the run was honest. See `docs/threat-model.md`.

## Docs
`docs/architecture.md` · `docs/threat-model.md` · `docs/benchmark-methodology.md` · `docs/evidence-signing.md` · `docs/deployment.md` · `docs/live-evaluation.md` · `docs/kiro-development.md` · `docs/hackathon-compliance.md` · `docs/demo-script.md` · `evidence/final-verification.md`

## License
MIT
