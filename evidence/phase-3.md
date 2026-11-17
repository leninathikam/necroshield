# Phase 3 evidence — replay and benchmark

Outcome: **passed for deterministic intention replay**. The saved results are
[benchmark.json](benchmark.json); every pair includes version/digest provenance.

```text
python manage.py benchmark
```

The benchmark actually executes seven fresh paired workers: six inert attacks
and one benign control. Observed results: baseline attack effects 6/6, protected
attack effects 0/6, protected task completion 7/7, blocked dispatches 6, and false
positives 0/14 legitimate calls. The benign control completes without a denial.
Provider cost is `null` because no model provider is called.

Both sides receive the same versioned intention tape, with separate initial
worlds and distinct UUIDs. Denial does not cause replanning. The test suite verifies
state isolation, report derivation from document data, changed data not producing
a hardcoded success, scenario provenance, and deterministic effect outcomes.

Run timings measure local computation. Benchmark latency includes process startup
and the sequential pair executions, excluding the subsequent database commit.
Exact observed values and timestamps are in the artifact, not a promised runtime.

The official MCP SDK stdio test initializes a real `ClientSession`, discovers
tools, reads a synthetic invoice, and verifies a policy-denied sandbox call with
no effects. The dashboard's fixture worker uses direct typed gateway calls; it
does not send every arena event over MCP transport. The separately tested MCP
surface shares that gateway and exposes read-only benchmark inspection for Kiro.

These deliberately vulnerable deterministic fixtures are not a measured LLM
population. No stochastic LLM robustness result is claimed.
