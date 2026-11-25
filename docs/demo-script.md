# Demo script (target 2:55)

Record against a running instance. On the free Render plan, open the site and wait for `/api/health` first so the recording does not include the cold start. Every number on screen comes from that instance. Say only what the screen shows. The 15-second version is the first two rows.

**The primary sequence is always: Attack → Policy generation → Counterfactual test → Human approval → Independent verification.** The dashboard runs it in one panel, and Attack Theatre shows the same five steps in full.

| Time | Screen | Action | What to say |
|---|---|---|---|
| 0:00 | Dashboard, sequence panel | Attack "Malicious tool-response instruction". Press **Run the sequence**. | "NecroShield attacks an agent's tool use on synthetic data. Step one, **Attack**: the unprotected agent sent a customer record to an outside address. That is a real effect in an in-memory sink." |
| 0:20 | Step 2 | Read the line | "Step two, **Policy generation**: candidate policies are built from the trusted task, and the ones that let the forbidden effect through are rejected outright." |
| 0:35 | Step 3 | Read the decisive denial | "Step three, **Counterfactual test**: lift this one denial and the attack comes back. That is the denial that mattered." |
| 0:50 | Step 4 | Point at the waiting message, then press **Approve and run** | "Step four, **Human approval**: nothing ran under the generated policy until I pressed this." |
| 1:05 | Step 5 | Read the verifier line | "Step five, **Independent verification**: the standalone verifier re-derives the hash chain, every policy decision and the outcomes from recorded effects. This button uses the server's copy. For a check that does not trust this server, download the export and run `python scripts/verify_evidence.py` on your own machine." |
| 1:25 | Attack Theatre | Scenario "Memory overwrite with an allowed key" (held-out). **Run Attack Theatre**; stop at stage 4 | "The Policy Lab suggested one policy from development scores alone. On this held-out attack it lets the forbidden effect through. The candidates here are scored after seeing this attack, so what they select is not a held-out result. The hand-written reference row is the author's own policy, written knowing the attack. It is a reference point, not a rival." |
| 1:55 | Policy Lab | The two strategy tables | "Plan-conditioned policies are built from each scenario's own plan, so their held-out numbers are not a generalisation test. Only the development-fitted policies are, and they are weak. Held-out results also shaped the objectives and the corpus, and the page says so." |
| 2:20 | Attack Theatre → Security patch | Deployed policy: the one built for another attack. **Compile security patch** | "A patch built for one attack was deployed and a sibling attack got through. The compiler reproduces it, proposes a fix, runs a regression spec, and applies nothing." |
| 2:40 | MCP Trust | Pick "description injection", **Inspect** | "A changed tool description is a diff, and activation is refused until someone approves that exact digest." |
| 2:50 | GitHub `.kiro/` | Show specs and steering | "Built with Kiro specs and steering; the development report states exactly what ran." |

Rules for the recording:
- If signing is not configured on the instance, skip the signature mention.
- Do not claim a real-model result: none exists. Everything shown is `deterministic_intent_replay`.
- Do not say the generated policy beats the manual policies. The manual policies were written by the author, who knew the attacks.
- Do not mention hooks having run: they have not been observed executing (`docs/kiro-development.md`).
- If a 429 appears, you shared a rate-limit bucket (see the proxy assumption in `docs/deployment.md`); wait a minute.
