# Threat model

## Protected assets and trusted authority

Assets are synthetic records, task-scoped capabilities, run-local memory, the
local sink, and the integrity of recorded outcomes. The host's real files, network
accounts, and secrets are intentionally absent from fixture tool capabilities.
Scenario definitions and executable application code are trusted developer input.
The policy is trusted code; the server establishes task scope. Browser-submitted
scenario identifiers select from a fixed registry, not executable source.

## Adversary

The attacker controls a versioned untrusted document or tool response inside a
fixture. Its instructions may ask the target to export synthetic data, alter
memory, use an unavailable tool, or cross a synthetic role boundary. Labels such
as `system`, a claimed role, and prompt text never grant capability. The reference
agent deliberately follows a bounded attack intention so the gateway can be tested.
No external targets, scanning, freeform payload execution, or user-supplied code
are supported.

## Boundaries

Browser -> validated API -> trusted registry -> bounded fixture executor -> policy
decision -> mock dispatch -> observed state -> evaluator -> stored evidence.

Baseline deliberately bypasses the task policy within the same inert arena. It
must never bypass host isolation. Protected dispatch requires allowlisting the
tool and its precise task-scoped arguments; deny is an observable pre-dispatch
event. Evaluation inspects effects rather than treating a model verdict or a
denial message as a verified security event.

## Isolation limits

The finite reference agent runs only application-owned code and data. A process
boundary and timeout, where used, provide fault containment, not a strong sandbox
for hostile Python. Synthetic tools have no network client, command runner, or
arbitrary filesystem capability. Do not enable arbitrary plugins, code execution,
or remote MCP servers in this runtime.

A hostile model or third-party MCP target requires a dedicated unprivileged
worker, an externally enforced network deny policy, CPU/memory/process quotas,
read-only filesystem, no host socket mounts, scoped credentials, and a stronger
isolation layer such as a VM. A Docker container alone is insufficient. These
controls are deployment prerequisites for a broader product, not claims that the
local fixture runner secures arbitrary workloads.

## Evidence and privacy

Only synthetic fixtures belong in the database. Redaction is applied before
evidence export; transformed records need a separately verifiable export digest.
Original event hashes cannot authenticate changed redacted payloads. An attacker
who controls database storage can rewrite a whole chain: retain exported digests
elsewhere if tamper evidence matters. No signing authority or external timestamp
service is claimed. Local history is append-oriented, not WORM storage.

The development API has no multi-user authentication. Bind it to loopback and use
it locally. A public deployment needs authenticated access, request budgets, TLS,
CSRF/origin review, restricted ingress, backups, retention rules, and tested
database migrations. Never expose the development server to the public internet.
