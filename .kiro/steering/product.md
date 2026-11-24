---
inclusion: always
---
# NecroShield product

NecroShield is an adversarial security-testing arena for AI agent and MCP tool workflows. It runs only against authorized synthetic environments.

- Each scenario runs twice from fresh state: a baseline run and a protected run. Both receive identical intended actions.
- The protected run checks a default-deny capability policy before every tool dispatch.
- Attack success is derived from observable synthetic effects (for example, a canary token reaching an in-memory sink). Model judgment is never reported as a verified security event.
- Legitimate task completion is measured alongside attack success, so false positives show up.
- Fixture results are labeled `deterministic_intent_replay`. Stochastic model evaluations are a separate track with their own model, sampling, repetition, and cost metadata.
- Design: charcoal, violet, and amber. Readable evidence first, keyboard accessible, responsive.
