# Demo script (target 2:45)

Record against a running instance, either `docker run` or the hosted URL. Every screen shows live results from that instance. Clear the database first so the counts start at zero.

| Time | Screen | Action | What to say |
|---|---|---|---|
| 0:00 | Dashboard | Show the empty recent-activity table | "NecroShield attacks an agent's tool use with synthetic data, then shows whether a policy stops the attack without breaking the real task." |
| 0:12 | Attack Arena | Select **Malicious tool-response instruction**. Point at the red highlighted line inside the customer record. | "This instruction sits in a tool response, not the prompt. The trusted task allows exactly these tools and arguments." Point at the grant list. |
| 0:35 | Attack Arena | Launch with the fixture target | "The same intended calls run twice, from fresh state: once unprotected, once behind default-deny." |
| 0:45 | Replay Lab | Baseline column: the attack succeeded. Protected column: `send_message` denied before dispatch, task completed. | "Baseline leaked the record to an outside address. Protected denied that one call before the tool ran, and billing still got its message." |
| 1:05 | Replay Lab | The decisive-decision table | "Lifting that one denial brings the attack back. That is an exact counterfactual, not a guess." |
| 1:15 | Execution Graph | Play the protected run | "Each edge is a chained event. Amber dashed means denied at the gateway." |
| 1:30 | Attack Arena | Target **Fixture agent over MCP**, **Document injection**, Launch | "The same attack through a real MCP client session. The gateway sits in front of every MCP tool." |
| 1:45 | Policy Inspector | Add a `send_message` grant and run | "A weaker policy changes the result, and the evidence records it as custom." |
| 2:00 | Benchmark Studio | Run benchmark | "Six attack classes and a benign control: baseline 6 of 6 attacks succeed, protected 0 of 6, task completion 7 of 7, no false positives. Cost is null because fixture runs make no model calls." |
| 2:20 | Evidence Explorer | Download the bundle, upload it (verified). Edit one number in the file, upload again (rejected). | "The verifier is a standalone script with no app imports. It recomputes every metric from the evidence." |
| 2:35 | GitHub `.kiro/` | Show specs, steering, hooks | "Built with Kiro specs, steering, and hooks. The development log in docs/kiro-development.md lists exactly what ran." |
| 2:45 | end | | |
