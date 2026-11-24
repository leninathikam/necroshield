# Requirements: web platform, MCP sandbox, and evaluation tracks

Builds on `phase1-vertical-slice`. Requirements R1 to R5 there still apply.

## R6 Core hardening
- R6.1 Grants, policies, and scenarios SHALL be immutable after construction.
- R6.2 WHEN a scenario, policy, grant, or check is invalid THEN construction SHALL raise (fail closed).
- R6.3 Tool arguments SHALL be exact `str`, identifier-named, bounded, and free of control characters.
- R6.4 Only the gateway SHALL call tool dispatch.
- R6.5 Tools SHALL NOT truncate output; over-limit output SHALL be an error.
- R6.6 Hashed events SHALL be identical across supported Python versions (golden vector).

## R7 Scenarios
- R7.1 The catalog SHALL contain document injection, tool-response injection, unauthorized record access, data exfiltration, scope manipulation, memory poisoning, and a benign control.
- R7.2 Each SHALL define a trusted task, attacker surface, forbidden behaviour, observable attack and task checks, version, digest, and default policy.
- R7.3 Each SHALL have a pinned regression test of its baseline and protected outcomes.

## R8 API
- R8.1 The API SHALL reject unknown fields and invalid policies with 422.
- R8.2 Responses SHALL withhold security conclusions for evidence that fails verification.
- R8.3 Writes SHALL require an allowed origin when an Origin header is present; bodies over 256 KB SHALL be rejected; writes SHALL be rate limited.

## R9 MCP
- R9.1 An MCP server built on the official SDK SHALL expose the six synthetic tools.
- R9.2 Every MCP tool call SHALL pass through the gateway; a denied call SHALL return an MCP error with no side effect.

## R10 Counterfactual lab
- R10.1 Users SHALL be able to run a scenario with an edited policy, recorded as `custom`.
- R10.2 For each protected denial, the system SHALL report whether lifting only that denial changes the outcome.

## R11 Live agent evaluation
- R11.1 A separate track SHALL run a real model in a multi-turn tool loop through the gateway.
- R11.2 It SHALL record provider, model, temperature, usage, cost (when pricing is configured), latency, and failures.
- R11.3 WHEN no provider is configured THEN the track SHALL report itself unavailable and SHALL NOT simulate results.
- R11.4 Provider URLs SHALL be HTTPS and on an allowlist.

## R12 Benchmark
- R12.1 Metrics SHALL state numerators and denominators and use only verified default-policy pairs.
- R12.2 A downloadable bundle SHALL let the standalone verifier recompute every metric.

## R13 Interface
- R13.1 Screens: Dashboard, Attack Arena, Execution Graph, Replay Lab, Policy Inspector, Evidence Explorer, Benchmark Studio.
- R13.2 Attacker content SHALL render as inert text.
- R13.3 Keyboard access, visible focus, reduced-motion support, and layouts usable at 412 px width.

## R14 Delivery
- R14.1 CI SHALL run core, API, scenario, evidence, frontend, browser, container, dependency, and secret checks.
- R14.2 A single container SHALL serve the API and frontend as a non-root user.
