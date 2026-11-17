# Phase 2 evidence — policy and forensics

Outcome: **passed for the local fixture runtime**. See the final counts and
environment in [the evidence index](README.md).

Executed acceptance paths include `backend/tests/test_policy.py`,
`test_engine.py`, `test_independent_review.py`, and `test_independent_verifier.py`.
The full backend suite and focused post-review runs exercised these paths.

- Hypothesis generated unknown tools and out-of-scope document identifiers.
- Invalid arguments, role claims, unavailable tools, and external destinations
  were denied with zero dispatched effects.
- Independent API tests verified Origin rejection before dispatch, including
  the unrelated local app's origin, plus streaming and declared body limits.
- Evidence tests detected mutation, missing chain links, mode-inconsistent
  authorization events, and contradictory effect data.
- Credential aliases were redacted recursively before hashing, including nested
  `access_token`, `client_secret`, and `apiKey` synthetic examples.

The independent verifier imports no application modules:

```text
python scripts/verify_evidence.py evidence/document-injection.json
```

It checks the whole-export digest, both event chains, mode-specific dispatch
order, and agreement between observed effects, completion events, and metrics.
It does not prove authorship or provide external notarization. Review findings
and their executed regressions are in [the independent review](../docs/security-review.md).
