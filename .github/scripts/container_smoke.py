"""Smoke test against a running container, using only the standard library. Fails loudly."""

import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/")
HOST = BASE.split("://", 1)[1]


def call(method, path, body=None, headers=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"content-type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def ok(cond, what):
    if not cond:
        sys.exit(f"FAIL: {what}")
    print(f"ok  {what}")


# Seeded benchmark exists on first boot.
status, body = call("GET", "/api/benchmark")
bench = json.loads(body)
ok(status == 200 and bench["missing_scenarios"] == [], "seeded benchmark covers every scenario")
ok(bench["summary"]["attack_success"]["protected"]["numerator"] == 0, "protected attack success is 0")

# All seven pages are served by the deployed build.
for page, text in [("/", "NecroShield"), ("/arena/", "Attack Arena"), ("/graph/", "Execution Graph"),
                   ("/replay/", "Replay Lab"), ("/policy/", "Policy Inspector"),
                   ("/evidence/", "Evidence Explorer"), ("/benchmark/", "Benchmark Studio"),
                   ("/theatre/", "Attack Theatre"), ("/lab/", "Policy Lab"), ("/trust/", "MCP Trust")]:
    status, body = call("GET", page)
    ok(status == 200 and text.encode() in body, f"page {page} served")

# Browser-style write from the deployed origin, with no origin configured on the server.
same = {"origin": f"http://{HOST}", "x-forwarded-for": "198.51.100.7"}
status, body = call("POST", "/api/runs", {"scenario_id": "tool_response_injection"}, same)
run = json.loads(body)
ok(status == 201 and run["verification"]["verified"], "same-origin run accepted and verified")
ok(run["summary"]["baseline"]["attack_succeeded"] and not run["summary"]["protected"]["attack_succeeded"]
   and run["summary"]["protected"]["task_completed"], "baseline compromised, protected blocked, task completed")

status, _ = call("POST", "/api/runs", {"scenario_id": "benign_invoice"},
                 {"origin": "https://evil.example", "x-forwarded-for": "198.51.100.8"})
ok(status == 403, "cross-origin write rejected")

status, body = call("POST", "/api/mcp/replay", {"scenario_id": "document_injection"}, same)
ok(status == 200 and json.loads(body)["outcome"]["attack_succeeded"] is False, "MCP sandbox path works")

# Rate-limit key comes from the proxy hop, not from anything the client adds on the left.
k1 = json.loads(call("GET", "/api/client-key", headers={"x-forwarded-for": "203.0.113.1"})[1])["client_key_hash"]
k2 = json.loads(call("GET", "/api/client-key", headers={"x-forwarded-for": "9.9.9.9, 203.0.113.1"})[1])["client_key_hash"]
k3 = json.loads(call("GET", "/api/client-key", headers={"x-forwarded-for": "203.0.113.2"})[1])["client_key_hash"]
ok(k1 == k2 != k3, "forged left-hand X-Forwarded-For entries do not change the client key")

codes = [call("POST", "/api/verify", {}, {"x-forwarded-for": "192.0.2.50"})[0] for _ in range(7)]
ok(codes[:5] == [200] * 5 and codes[5] == 429, f"per-client write limit enforced {codes}")
ok(call("POST", "/api/verify", {}, {"x-forwarded-for": "192.0.2.51"})[0] == 200, "other clients unaffected")

# Malformed and hostile requests do not take the service down.
ok(call("POST", "/api/verify", b"[" * 120000 + b"]" * 120000, {"x-forwarded-for": "192.0.2.60"})[0] in (400, 413),
   "deeply nested JSON rejected")
ok(call("POST", "/api/verify", b"{not json", {"x-forwarded-for": "192.0.2.61"})[0] == 422, "invalid JSON rejected")
ok(call("POST", "/api/runs", {"scenario_id": "x" * 10000}, {"x-forwarded-for": "192.0.2.62"})[0] == 422,
   "oversized field rejected")

# 2.0: evolution, theatre, patch compiler, MCP trust, signing posture.
status, body = call("GET", "/api/evolution")
evo = json.loads(body)
ok(status == 200 and evo["selected"] == "scoped_trace" and evo["corpus"]["scenarios"] == 22, "evolution selects scoped_trace over 22 scenarios")
ok(evo["selected_held_out_leaks"] == ["memory_overwrite_allowed_key"], "the held-out failure of the selected policy is reported, not hidden")
status, body = call("GET", "/api/theatre/tool_response_injection")
ok(status == 200 and json.loads(body)["selected"] == "scoped_trace", "theatre selects a verified candidate")
status, body = call("POST", "/api/theatre/tool_response_injection/approve", {"strategy": "scoped_trace"}, same)
approved = json.loads(body)
ok(status == 201 and approved["verification"]["verified"] and not approved["summary"]["protected"]["attack_succeeded"], "approved candidate runs and verifies")
status, body = call("GET", "/api/patch?scenario_id=data_exfiltration&base=violation_patch&base_from=tool_response_injection")
ok(status == 200 and json.loads(body)["all_cases_pass"], "patch compiler output passes its own regression spec")
status, body = call("POST", "/api/mcp/inspect", {"drift": "tool_added"}, same)
ok(status == 200 and json.loads(body)["activate"] is False, "MCP drift is refused")
status, body = call("POST", "/api/mcp/replay", {"scenario_id": "document_injection", "drift": "description_injection"}, same)
ok(status == 409, "MCP replay on drifted tools is refused before any call")
ok(json.loads(call("GET", "/api/signing")[1])["enabled"] is False, "signing is off without a configured key")
ok(call("GET", "/api/benchmark/bundle?signed=true")[0] in (409,), "signed bundles are unavailable without a key")

# Paid inference cannot be triggered publicly.
status, body = call("GET", "/api/live/status")
ok(json.loads(body)["available"] is False, "live status reports unavailable to visitors")
ok(call("POST", "/api/live/runs", {"scenario_id": "document_injection"}, {"x-forwarded-for": "192.0.2.70"})[0] == 403,
   "live runs refused without an operator token")

ok(call("GET", "/api/health")[0] == 200, "service still healthy after hostile requests")
