# Requirements: NecroShield 2.0

Baseline: commit `b91d2ed` (2026-11-24).
- Seven scenarios: six attack classes and one benign control.
- Fixture benchmark: baseline attack success 6/6, protected 0/6; task completion 6/7 (baseline) and 7/7 (protected); false positives 0/1; denial rate 6/36.
- Backend suite in CI: 198 passed (`8ee68ff`). Core suite in the sandbox: 138 passed, 4 skipped.

Requirements R1–R14 from earlier specs still apply. Priorities: P0 must ship; P1 if P0 is green; P2 optional.

## R15 Closed-loop security evolution (P0)
- R15.1 A Red Team SHALL generate bounded attack variants of a scenario only from approved, seeded fixture transformations. The same seed SHALL give the same variants.
- R15.2 A Blue Team SHALL propose policy candidates as structured capability grants derived from the scenario's trusted plan and the observed violations.
- R15.3 An independent evaluator SHALL run every candidate against attack variants and benign controls through the existing gateway.
- R15.4 No component SHALL modify the enforcement engine, scenario defaults, or any stored policy. A candidate takes effect only when a human explicitly runs it, and is then recorded as `custom`.
- R15.5 Every component SHALL work deterministically without API keys.

## R16 Counterfactual policy optimizer (P0)
- R16.1 Candidates SHALL be scored on forbidden effects prevented, legitimate tasks completed, false-positive denials, complexity, and evaluation time. Every metric SHALL carry its numerator and denominator.
- R16.2 A candidate that lets any forbidden effect occur in the development set SHALL be rejected.
- R16.3 The system SHALL report the non-dominated set (the Pareto frontier) and SHALL NOT call any candidate globally optimal.
- R16.4 The selected candidate, the comparison table, and per-run counterfactual evidence SHALL be exportable.

## R17 Held-out evaluation (P0)
- R17.1 Scenarios SHALL be split into development and held-out sets before any selection runs. Synthesis strategies SHALL be selected using development scenarios only.
- R17.2 The benchmark SHALL compare four arms (unprotected, blanket deny, manual policies, synthesized policies) on both sets, with exact denominators.
- R17.3 Seeded variations SHALL be reported separately from base scenarios and SHALL NOT be counted as new attack classes.
- R17.4 The corpus SHALL contain at least 10 benign controls.

## R18 Security patch compiler (P1)
- R18.1 From an observed failure (an attack effect under some policy), the system SHALL produce a JSON patch with the base policy, the proposed policy, structured operations, a regression-test specification, and evaluation results on development and held-out sets.
- R18.2 A patch SHALL be applied only by an explicit human run.

## R19 Information-flow constraints (P1) — NOT IMPLEMENTED
- R19.1 Synthetic records SHALL carry classification labels. Labels SHALL propagate through the supported transformations: verbatim inclusion of labeled text, and attachment by reference.
- R19.2 Policies MAY constrain which destinations may receive each label. Violations SHALL be denied before dispatch.
- R19.3 Documentation SHALL list the supported transformations and SHALL NOT claim general information-flow tracking.

## R20 MCP trust inspector (P1)
- R20.1 The sandbox's tool manifest (name, description, input schema) SHALL be hashed and compared with an approved manifest.
- R20.2 Synthetic drifted manifests SHALL be detected, diffed in readable form, and refused activation unless approved.
- R20.3 No external MCP server SHALL be contacted.

## R21 Signed evidence (P1)
- R21.1 Benchmark bundles MAY be signed with Ed25519 using a key from the environment.
- R21.2 The standalone verifier SHALL check signatures with a supplied trusted public key, without third-party packages.
- R21.3 Documentation SHALL state what a signature proves and what it does not.

## R22 Judge experience (P0)
- R22.1 An Attack Theatre SHALL run, from one click: attack, compromise, policy synthesis, Pareto selection, protected replay, and verification. Every element SHALL come from backend responses.
- R22.2 A first-time visitor SHALL understand the page's point within 15 seconds and be able to finish the flow within three minutes.

## R23 Free-tier deployment (P0)
- R23.1 The service SHALL stay under 512 MB RSS during the judge flow, measured in CI.
- R23.2 Optimizer work per request SHALL be bounded: number of candidates, number of variants, and cached results.
