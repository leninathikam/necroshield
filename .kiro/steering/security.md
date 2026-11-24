---
inclusion: always
---
# Security rules

- Synthetic records, inert payloads, and bounded mock tools only.
- No arbitrary command execution, public-target scanning, production credentials, or uncontrolled network destinations in the execution surface.
- Authorization is default-deny and is enforced before dispatch. A denied call must never reach tool code.
- Redact secrets before an event is hashed. Events are ordered and hash-linked.
- Validate origins, limit request bodies, and use strict Pydantic contracts (reject unknown fields).
- Fixture workers get time, memory, concurrency, and output limits. Do not treat a container alone as isolation.
- Keep secrets out of the repository, logs, and exports.
- Describe integrity guarantees and their limits honestly. A hash chain detects accidental or naive edits; it does not stop an attacker who can rewrite the whole chain.
