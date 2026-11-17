---
inclusion: always
---

# Code quality

Use explicit Pydantic request/response models and TypeScript API types. Validate at entry points. Give invariants descriptive names; keep dispatch and policy logic auditable. Avoid generic plugin loading or framework layers without a concrete need.

Return useful bounded API errors, preserve exception context in structured internal logs, and avoid exposing tracebacks to clients. Database schema changes require migrations. Persist only committed complete records or explicit failure states.

Do not merge fixture and stochastic evaluation results. Never use a language model's judgment as a verified security event. Record unavailable model cost as null, rather than zero.

Run checks that exercise changed behavior. Document failing checks and environment limits accurately; do not check off tasks from code inspection alone.
