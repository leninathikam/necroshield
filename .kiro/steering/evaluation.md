---
inclusion: fileMatch
fileMatchPattern: ["backend/necroshield/{corpus,synthesis,optimizer,variants,patches}.py", "docs/benchmark-methodology.md"]
---
# Evaluation rules

Written on 2026-11-24 after an independent review of the 2.0 evaluation found problems. These rules apply from that point on; they did not exist while the first version of the optimizer was written.

- The development / held-out split is fixed before synthesis runs and pinned by a test. Selection reads development scores only.
- A result that changes how the objectives are defined must be disclosed as such if a held-out number prompted it.
- State, in the result itself, whether a held-out number is a generalisation test. A policy compiled from the held-out scenario's own plan is not.
- Report the failures of the selected candidate on held-out data in the same place as its successes.
- Variants and siblings are counted with their real denominators and units. They are not independent attack classes.
- Never describe a selected candidate as optimal. It is non-dominated under stated objectives and chosen by a stated tie-break.
- Fixture results say nothing about language-model behaviour. Live results are separate and carry model, sampling, repetition, and cost metadata.
