# Live Agent Evaluation

**Status: not run.** No provider credentials were available. Every live-track test in CI uses an `httpx.MockTransport` test double, and nothing in the repository is real-model evidence.

## What the track does
A real model gets the scenario's trusted task and the six synthetic tools as function definitions. It runs a multi-turn loop: every tool call it makes goes through the same gateway as the fixture track, and a denied call returns `DENIED by policy: ...` to the model. The run is recorded as a hash-chained `necroshield.live/1` export, which records:
- every model turn: content, refusal, finish reason, and requested tools;
- every call and its decision;
- token usage, estimated cost, and provider-reported cost;
- latency;
- the observed outcome.

Live results are never merged into the fixture metrics. A model may act differently on every run, so each run is reported on its own.

## Protocol
The adapter uses the OpenAI-compatible `POST {base}/chat/completions` protocol with `tools` (type `function`), `tool_choice: "auto"`, `temperature`, and `max_tokens: 512`. Tool results go back as `role: "tool"` messages with the `tool_call_id`. When an assistant turn has no tool calls, the `tool_calls` key is omitted rather than sent as null. On `openrouter.ai`, requests also send `usage: {"include": true}`, and the per-request `usage.cost` is recorded as the provider-reported cost.

**Validated against the documented request and response shapes**, not against a live endpoint. See `test_request_and_response_follow_the_openrouter_protocol` in `backend/tests/test_live.py`. The first real run is the end-to-end protocol check: if it fails, the export records `provider error: HTTP <status>` and nothing is charged beyond that request.

Handled outcomes, all with evidence kept:
- HTTP errors, including 429;
- timeouts and connection errors;
- malformed JSON or unexpected shapes;
- refusals (the `refusal` field with no tool calls);
- invalid tool names or arguments;
- turn, call, time, and per-turn prompt bounds.

## Low-cost configuration (example: OpenRouter, `openai/gpt-4o-mini`)
List price checked 2026-11-24: $0.15 per million input tokens, $0.60 per million output tokens ([OpenRouter](https://openrouter.ai/openai/gpt-4o-mini)). Recheck before running.
```
export NECROSHIELD_LLM_BASE_URL=https://openrouter.ai/api/v1
export NECROSHIELD_LLM_ALLOWED_HOSTS=openrouter.ai
export NECROSHIELD_LLM_PROVIDER=openrouter
export NECROSHIELD_LLM_MODEL=openai/gpt-4o-mini
export NECROSHIELD_LLM_PRICE_IN_PER_MTOK=0.15
export NECROSHIELD_LLM_PRICE_OUT_PER_MTOK=0.60
export NECROSHIELD_LLM_API_KEY=...          # paste into your shell only; never commit it
```
OpenRouter also lets you set a credit limit on the key itself. Set it to $2 as a second, provider-side cap.

## Running a budgeted experiment ($2 maximum)
Run this on your own machine or in the server shell, never through the public site:
```
cd backend
pip install -r requirements.txt -c constraints.txt
python -m necroshield live --out live-results --scenarios all --modes baseline,protected \
    --repetitions 3 --temperature 0 --budget-usd 2 --ledger live-results/ledger.json
python ../scripts/verify_evidence.py live-results/<run>.json
```
- Before each run, the ledger reserves the run's worst-case cost: 8 turns × (8000 prompt tokens + 512 completion tokens) at list price. For gpt-4o-mini that is about $0.012. A run that could push spending past $2 does not start.
- After each run, the ledger records the provider-reported cost when present, and otherwise the estimate from usage and list prices.
- Without prices, the command refuses to start, because cost could not be bounded.
- The 42 runs above (7 scenarios × 2 modes × 3) reserve at most about $0.49.

`live-results/summary.json` holds the live metrics, separate from the fixture benchmark. Each run's JSON can be uploaded in the Evidence Explorer or checked with the standalone verifier.

## Public safety
- The browser never receives the key, the base URL, or any request headers. `/api/live/status` returns only the provider label and model name, and always `available: false`.
- `POST /api/live/runs` returns 403 unless `NECROSHIELD_LIVE_OPERATOR_TOKEN` (at least 32 characters) is set, and 401 for a wrong token. It also enforces one run at a time and a per-process run budget.
- Do not set provider variables on the public judge deployment.

## What a live run can and cannot show
It can show how one model, at one temperature and with this prompt, behaved on these synthetic tasks in those runs, and whether the gateway stopped what it tried. It cannot show how often the model would do so in general unless enough repetitions are run, and the count must be reported with any rate.
