# Final verification: NecroShield 2.0 (2026-11-24)

Code commit verified: `7dd47d4039ff52e9bc334a02406386c1d99e4dea` (all ten CI jobs green). Baseline before 2.0: `b91d2ed`. Later commits are documentation only; they are listed at the end.

Everything below was observed in this session: locally in the Kiro Web sandbox (Python 3.11, standard library and pytest only) or in GitHub Actions on `leninathikam/necroshield`.

## CI result for 7dd47d4
| Job | Result |
|---|---|
| core tests, Python 3.11, 3.12, 3.13, 3.14 | pass (292 passed, 18 skipped on 3.11: the skips need packages the core job omits) |
| api, mcp, live-loop, signing, patch, and manifest tests (nothing may be skipped) | **393 passed, 0 skipped** |
| benchmark and standalone verification | pass; pinned bundle `7 pairs, summary recomputed` |
| frontend lint, typecheck, build, `npm audit` | pass |
| playwright, desktop and mobile, against the real API | **34 passed** |
| container under production conditions | pass: assigned PORT, root-owned disk, restart persistence, reset, free-plan configuration, **peak memory 69 MB (limit 512 MB)** |
| pip-audit and gitleaks | pass |

Local, in the sandbox: `python3 -m pytest -q -o addopts=""` gave 289 passed, 19 skipped. The skipped tests need FastAPI, the MCP SDK, `cryptography`, `httpx`, or Hypothesis, which this sandbox cannot install; CI ran them.

## Results (deterministic fixture replay)
`python -m necroshield evolve --variants 3`, corpus of 22 scenarios (11 attacks in 6 classes, 11 controls; development 10, held-out 12):

| Strategy | Dev stopped | Dev tasks | Dev legit denied | Held-out stopped | Held-out tasks | Sibling pairs (dev / held-out) |
|---|---|---|---|---|---|---|
| allow_all | 0/5 rejected | 8/10 | 0/40 | 0/6 | 11/12 | 0/6, 0/5 |
| deny_all | 5/5 | 0/10 | 40/40 | 6/6 | 0/12 | 6/6, 5/5 |
| tool_allowlist | 2/5 rejected | 9/10 | 0/40 | 0/6 | 11/12 | 4/6, 0/5 |
| violation_patch | 5/5 | 10/10 | 0/40 | 6/6 | 12/12 | 4/6, 1/5 |
| **scoped_trace** (suggested) | 5/5 | 10/10 | 0/40 | **5/6** | 11/12 | 6/6, 4/5 |
| exact_trace | 5/5 | 10/10 | 0/40 | 6/6 | 12/12 | 6/6, 5/5 |
| global_tool_allowlist | 0/5 rejected | 8/10 | 0/40 | 0/6 | 11/12 | 0/6, 0/5 |
| global_scoped | 5/5 | 10/10 | 0/40 | 4/6 | 7/12 (4/47 legit calls denied) | 6/6, 1/5 |

Four arms, held-out (12): unprotected 0/6 stopped, 11/12 tasks; blanket deny 6/6, 0/12; manually authored 6/6, 12/12; **synthesized (`scoped_trace`) 5/6, 11/12**. Cost is `null` throughout: no model was called.

Original seven scenarios (`python -m necroshield benchmark`, unchanged): unprotected attack success 6/6, protected 0/6; task completion 6/7 vs 7/7; false positives 0/1; denial rate 6/36.

## What these results do not show
- Held-out numbers for per-scenario strategies are **not a generalisation test**: each policy is compiled from the scenario's own plan. Only `global_scoped` and `global_tool_allowlist` are fitted on development alone, and they generalise poorly.
- The suggested policy **leaks one held-out attack** (`memory_overwrite_allowed_key`, a free-text channel). The Lab and the results JSON say so.
- Seeded variants change attacker values only; four attacks have none. They are not independent attack classes.
- The corpus is small and author-built; the split is author-chosen. The sibling-transfer objective was added after a held-out result; `memory_overwrite_allowed_key` was added after a review. Both are disclosed.
- None of this says anything about how a language model behaves. **No real-model run has happened.**

## Security findings
### Earlier review (commit 8f39d51 → be8e159)
28 findings, fixed with regression tests. See `docs/kiro-development.md`.

### Independent review of 2.0 (b91d2ed → e7dfd05): 20 findings
| Finding | Severity | Resolution |
|---|---|---|
| Held-out "synthesized" arm is compiled per scenario, so it is not a generalisation test | high | Relabeled everywhere; rows carry `held_out_basis`; the Lab leads with global results and the selected policy's held-out failure |
| `check_patch` accepted a forged `allow_all` patch with a trimmed spec | high | Recompiles from stated inputs and compares every field |
| MCP drift detection ignored property descriptions, enums, patterns, lengths, formats, defaults, `additionalProperties`, annotations | high | Hash covers the full canonical schema and annotations; nine evasion probes are now tests |
| Signed-file CLI dropped `--scenario-digest/--policy-digest` yet printed "(digests pinned)" | medium | Digests are applied to the payload; the message is accurate |
| Small-order public key made any signature verify | low | Strict verification rejects small-order keys and nonces |
| Transfer counted as independent evidence when true by construction; ordered-pair counts | medium | Flagged `by_construction`, unit stated |
| Variants overstated ("3 per attack"; four have none) | medium | Real counts reported |
| Free-text channel unexercised by the corpus | medium | Held-out attack added; selected policy now shown failing it |
| Held-out data influenced objective design | medium | Disclosed (cannot be undone) |
| Capability table is the server's own annotation; approval is an unauthenticated parameter; inspector crashed on list-typed properties | low-medium | Page and docs say so; list types handled |
| `_patch` CLI wrote a patch before re-checking it; stale-response races on the Theatre and Trust pages; hard-coded "null" cost; chart captions overclaiming | low-medium | Fixed |
| README and threat model said exports are never signed; no 2.0 docs | medium | Rewritten; `docs/evidence-signing.md` added |
| Information-flow (R19) undelivered | requirement | **Not implemented**; marked as such |

Defects found by CI, not by review, and fixed: stage reveal stopped one stage short so no one could approve a candidate; `ManifestDrift` raised inside the SDK's async session was wrapped in an `ExceptionGroup` and would have returned a 500; two commits omitted `scripts/verify_evidence.py` from staging, so CI tested an older verifier than my local run.

Screenshots (desktop 1440 px and Pixel 7) showed overlapping chart labels and a clipped verdict column; both were fixed.

## Known vulnerabilities and limits
- Evidence is not signed by default; a signature proves who vouched, not honesty. See `docs/evidence-signing.md`.
- Rate limits are per process and in memory; approvals of MCP drift are an unauthenticated request parameter in the demo.
- No information-flow tracking. Policy pinning of attachment references constrains some flows; it is not IFC.
- Approving candidates writes stored pairs, so a client can use its write budget to evict older non-benchmark history (retention keeps the benchmark population).
- The sandbox cannot reach external hosts, so deployment, hosted end-to-end checks, and external testing were not possible here.

## Deployment status
**Not deployed.** No public URL exists. `render.yaml` is the participant's free-plan blueprint (database in `/tmp`, seed on start, proxy-hop rate keys); CI runs that exact configuration and measures memory (69 MB peak). The participant commit `d5b4f7a` indicates a deployment was being set up; I could not reach any host to confirm it.

## Live-model status
**Not run.** The adapter, budgeted operator CLI (`python -m necroshield live`, $2 cap), and cost accounting are implemented and tested only with a scripted transport double. Request and response shapes follow OpenRouter's documented format but have not been checked against a live endpoint. See `docs/live-evaluation.md`.

## Judge access
No login. Open the site, press **Run Attack Theatre**, then Approve. Everything is synthetic. Paid inference is not reachable from the browser. Signing is off unless the operator configures a key.

## Submission readiness
Code and documentation: ready. Blocking, and requiring you: (1) a public URL kept up through January 29, 2027, with the post-deploy checks in `docs/deployment.md`; (2) the demo video from `docs/demo-script.md`; (3) re-reading the Devpost rules (the page returned 403 to every fetch from this sandbox). Optional: provider credentials for a real-model run. No Kiro Crew or blog bonus is claimed.
