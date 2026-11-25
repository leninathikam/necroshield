# Demo script (target 2:50)

Record against a running instance with a fresh database. Every number on screen comes from that instance. Say only what the screen shows. The 15-second version is the first two rows.

| Time | Screen | Action | What to say |
|---|---|---|---|
| 0:00 | Attack Theatre | Scenario "Malicious tool-response instruction". Press **Run Attack Theatre**. | "NecroShield attacks an agent's tool use on synthetic data. An attack compromises an unprotected agent; a Blue Team proposes defenses; an independent evaluator tests them; I decide." |
| 0:12 | Stage 1 | Point at the red effects and the "attacker-driven" calls | "The unprotected agent sent a customer record to an outside address. That is a real effect in an in-memory sink." |
| 0:30 | Stages 2 to 3 | Red team variants, then the candidate table | "Red team only changes attacker values. Blue team proposes structured policies. The model cannot edit the enforcement engine." |
| 0:50 | Stage 4 | Rejected rows, the frontier chart, the decisive-denial table | "A policy that lets the attack through is rejected outright. Lifting this one denial brings the attack back." |
| 1:10 | Stage 5 | **Approve and run this candidate** | "Nothing runs until I approve. Baseline: attack succeeded. Protected: denied before dispatch, task completed, evidence verified." |
| 1:30 | Security patch | Deployed policy: the one built for another attack. **Compile security patch** | "A patch built for one attack was deployed and a sibling attack got through. The compiler reproduces it, proposes a fix, runs a regression spec on development and held-out, and applies nothing." |
| 1:55 | Policy Lab | The held-out finding panel, then the strategy table | "The suggested policy fails one held-out attack: it leaves free text open. For per-task policies the held-out numbers aren't a generalisation test, and the page says so." |
| 2:20 | MCP Trust | Pick "description injection", **Inspect** | "The sandbox's real tool listing is hashed. A changed description is a diff, and activation is refused until someone approves that exact digest." |
| 2:35 | Evidence Explorer | Upload a downloaded pair export (verified), then edit one value and upload again (rejected) | "A standalone verifier with no app imports re-derives every outcome. Signatures are optional and prove who vouched, not that the run was honest." |
| 2:50 | GitHub `.kiro/` | Show specs and steering | "Built with Kiro specs, steering and hooks; the development report states exactly what ran." |

If signing is not configured on the instance, skip the signature mention. Do not claim a real-model result: none exists.
