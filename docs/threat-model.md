# Threat model

## Assets
- Integrity of security conclusions (attack succeeded or blocked, task completed).
- The judge-facing service and its availability.
- Synthetic secrets in fixtures. These are not real, but are treated as secrets so that redaction gets exercised.

## Trust boundaries
1. **Attacker-controlled content → agent.** Documents and tool responses can contain injected instructions. The fixture agent obeys them by design, and a live model may obey them too.
2. **Agent → tools.** Every call crosses the gateway. Protected runs are default-deny before dispatch.
3. **Browser → API.** Untrusted input: JSON bodies, uploaded evidence files, and policy edits.
4. **Stored evidence → display.** The database file is not trusted. Every read re-verifies.
5. **API → model provider** (live track only). Outbound HTTPS goes only to an allowlisted host, with a key from the environment.

## Threats and controls
| Threat | Control | Test |
|---|---|---|
| Injected instruction causes an unauthorized call | Default-deny grants checked before `_invoke` | `test_denied_calls_never_reach_tool_code`, Hypothesis `test_denied_calls_never_dispatch_and_leave_no_side_effects`, MCP `test_authorized_read_denied_attempt_and_completed_task` |
| Bypass through another route to tool code | `_invoke` is private; an AST test allows only `gateway.py` to reference it | `test_only_the_gateway_references_tool_dispatch` |
| Argument smuggling (`str` subclasses, control characters, extra arguments, path traversal) | Exact-type and identifier checks, exact-match scopes on the raw value, and tool argument specs | `test_non_canonical_arguments_are_rejected_at_construction`, `test_arguments_outside_grant_are_denied`, `scope_manipulation` scenario |
| Policy mutated after its digest | Immutable grants and policies | `test_scenario_definitions_are_immutable` |
| Invalid scenario or policy runs with weaker rules | Construction-time validation that raises; API returns 422 | `test_invalid_scenarios_fail_closed`, `test_invalid_policies_and_checks_fail_closed`, `test_invalid_requests_fail_closed` |
| Truncation hides a leaked canary | No truncation: over-limit output is an error | `test_oversized_output_is_an_explicit_error_not_a_truncation` |
| Secrets in exports, database, or CLI | Redaction before hashing, on all exported fields, keys included | `test_secrets_in_intents_stay_out_of_export_store_and_cli` |
| Forged or edited evidence | Hash chain plus semantic checks in the standalone verifier: decisions re-evaluated against the policy, bound arguments re-derived, outcomes re-derived from chained per-call effects, the scenario header bound to its digest, and bundle arithmetic recomputed | Tamper cases in `test_evidence.py` and `test_review_regressions.py`, the Hypothesis single-edit property, bundle forgery tests |
| Edited database file | Verify on every read; conclusions withheld when verification fails | `test_tampering_with_the_database_file_is_reported_on_load` |
| Cross-site writes | Origin allowlist on unsafe methods | `test_cross_origin_writes_are_rejected` |
| Oversized requests | Streamed 256 KB limit | `test_oversized_bodies_are_rejected` |
| Request flooding and cost abuse | Per-client rate limits (read, write, and live buckets), a cap on stored pairs, one live run at a time, a per-process live-run budget, and live turn, call, and time budgets | `test_write_rate_limit`, `test_a2_store_refuses_pairs_past_its_cap` |
| Model provider used as an exfiltration channel | HTTPS plus host allowlist, key from the environment only | `test_provider_destination_must_be_https_and_allowlisted` |
| Stored XSS from scenario content | React text rendering only; no HTML injection APIs; CSP | e2e `arena shows inert injected source` |

## Out of scope and known limits
- **No authenticity.** Exports are not signed. A complete, self-consistent rewrite passes unless digests are pinned from a trusted source (`--pins`, from `GET /api/pins` or `python -m necroshield scenarios`). Pinning binds the scenario header (id, version, kind, checks, initial memory) and the policy. The test `test_fully_recomputed_forgery_is_caught_only_by_pinned_digests` documents this.
- **Some fields stay unverifiable.** Denial `reason` text, the content of `send_message` bodies built from attachments, and fact extraction from redacted output are recorded but not independently re-derived.
- **Rate limits are per process** and keyed on the client address. The container trusts `X-Forwarded-For` only from `FORWARDED_ALLOW_IPS` (default `127.0.0.1`). Set that to the hosting proxy's range; otherwise every client behind the proxy shares one bucket.
- **The CSP allows inline scripts**, which the Next.js static export requires. React text rendering, with no HTML injection anywhere, is the actual XSS control.
- **Database triggers** protect against accidents only. Anyone who can write the file can drop them, and verify-on-read is the real control.
- **The fixture agent is not a model.** Its results show what the gateway does to a fixed attack, not how any LLM behaves.
- **Isolation** is in-process. Tools touch only in-memory objects, and no tool opens files, sockets, or processes. The container adds a non-root user, but is not the security boundary.
