# NecroShield design

## Trust and execution model

The browser is an investigator interface. It sends a registered scenario ID to FastAPI. The registry supplies a trusted scope and versioned synthetic world. A typed fixture state machine creates a bounded intent plan; the baseline and protected runners each receive a fresh world. Policy evaluates before protected tool dispatch. Only inert local handlers exist.

```mermaid
sequenceDiagram
    participant UI as Investigator dashboard
    participant API as FastAPI
    participant Reg as Scenario registry
    participant GW as Policy gateway
    participant Tool as In-memory mock tool
    participant DB as Run store
    UI->>API: Create pair(scenario_id)
    API->>Reg: Validate scenario and scope
    Reg-->>API: Versioned world + fixed intents
    loop Independent baseline/protected worlds
        API->>GW: Typed intent + trusted context
        alt Protected and denied
            GW-->>API: Deny; no dispatch
        else Baseline or allowed
            GW->>Tool: Bounded typed call
            Tool-->>API: Observable effect/result
        end
        API->>API: Evaluate world effects; chain events
    end
    API->>DB: Persist pair and provenance
    API-->>UI: Real trace and measured outcomes
```

## Contracts and modules

- Registry: immutable versioned definitions, legitimate task, adversarial source, exact intent plan, trusted authorization scope, evaluator target.
- Policy: pure default-deny function; no LLM or untrusted-text authorization. Approved dispatch is an explicit branch after validation.
- Sandbox: in-memory synthetic documents, records, report, sink, roles, and memory. No dynamic code or external URLs.
- Runner/evaluator: bounded sequential execution; success derives from side effects and legitimate report content. A denial alone never establishes safety.
- Trace/evidence: ordered structured events with chained hashes; recursive redaction on export; original and exported digest semantics documented. No claim of cryptographic authenticity without a trusted digest/signature.
- Persistence/API: SQLAlchemy relational records and migrations; PostgreSQL target with SQLite development fallback. Invalid requests fail before execution; stored runs remain queryable by UUID.
- UI: Next.js server proxy to FastAPI; typed client; React Flow trace graph plus text timeline, paired cards, decision inspector, benchmark controls, history, and export.
- Development MCP: official SDK stdio server exposes read-only local result inspection. Kiro review agent receives only read and inspector tools.

## Architecture choices

Use a typed state machine for fixture replay: its finite intent plan is easy to audit and deterministic. LangGraph would add runtime/dependency complexity without providing needed behavior yet. Reconsider when adaptive multi-step model execution exists.

Use a small typed authorization function as the documented policy-as-code equivalent. Rego/OPA would add a process boundary and distribution dependency; migrate when operators need independent rule deployment. Preserve explicit trusted context and non-dispatch tests either way.

Avoid Redis until measured job duration or concurrency requires it. Never label synchronous bounded fixture execution as isolated arbitrary-agent execution. External model/agent workers require a reviewed sandbox with enforced egress, CPU/memory/time budgets, restricted mounts, capability minimization, and no production credentials.

## Failure handling and measurement

Unknown scenario IDs, unexpected properties, and invalid values produce validated client errors. Tool exceptions produce explicit failed evidence or an error response; never silently convert failures to security success. Database failures fail the request rather than return an unpersisted success.

Attack-success rates use malicious cases as denominator; benign controls measure false positives and legitimate utility. Report measured wall latency and calls. Provider cost is null where no model provider ran. Deterministic fixture results and stochastic LLM evaluations have different datasets and reports.

## Acceptance traceability

- R1: first document API round trip and Phase 1 report.
- R2: pure policy tests, generated adversarial arguments, denied-handler spy.
- R3: persistence/export round trip, redaction and hash-mutation tests.
- R4: pair replay identity/isolation, benign control, benchmark aggregation tests.
- R5: parametrized registry scenario tests after the first gate.
- R6: TypeScript build and Playwright real-API workflows; manual visual/keyboard review.
- R7: migration/database/API validation tests and restart checks.
- R8: `.kiro/scripts/validate_config.py`, truthful development log, separate Kiro runtime and submission evidence.
