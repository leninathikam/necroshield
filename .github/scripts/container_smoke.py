"""Smoke test against a running deployment, using only the standard library. Fails loudly.

    python3 container_smoke.py BASE_URL [--mode auto|direct|proxied]

The test reads the deployment's own configuration from /api/health (write limit, proxy hops, seeding) and
checks behaviour against that, so it works for any limit rather than a hard-coded one.

  direct   Nothing sits between this script and the app, so the script can simulate different clients by
           setting X-Forwarded-For. Expects exactly `limit` writes to succeed, then 429.
  proxied  A real proxy appends the true client address to X-Forwarded-For (Render, or the CI xff proxy).
           Forged headers cannot create new clients, so every request shares one bucket. Expects at most
           `limit` successes then 429, and prints the client key so it can be compared from another network.
  auto     proxied for https or a non-local host, otherwise direct.
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
BASE = ""
MODE = "direct"


def detect_mode(base: str, requested: str = "auto") -> str:
    if requested in ("direct", "proxied"):
        return requested
    parts = urllib.parse.urlsplit(base)
    return "proxied" if parts.scheme == "https" or (parts.hostname or "") not in LOCAL_HOSTS else "direct"


def probe_plan(mode: str, limit: int, proxy_hops: int, client_ip_header: bool) -> dict:
    """What the rate-limit probe must observe. Forging X-Forwarded-For only creates new clients when no proxy
    stands in front of the app, the app trusts that header, and no dedicated client-IP header is configured."""
    forgeable = mode == "direct" and proxy_hops >= 1 and not client_ip_header
    return {"distinct_clients": forgeable, "exact": mode == "direct", "limit": limit}


def judge_probe(codes: list, plan: dict) -> tuple:
    """Returns (passed, explanation) for the status codes of the final write probe, made from one client."""
    limit = plan["limit"]
    if 429 not in codes:
        return False, f"never rate limited after {len(codes)} writes (limit {limit})"
    first = codes.index(429)
    if any(c != 200 for c in codes[:first]):
        return False, f"unexpected status before the limit: {codes}"
    if plan["exact"]:
        return first == limit, f"{first} writes succeeded before 429, expected exactly {limit}"
    return 0 < first <= limit, f"{first} writes succeeded before 429 (the bucket is shared, so at most {limit})"


def call(method, path, body=None, headers=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"content-type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def ok(cond, what):
    if not cond:
        sys.exit(f"FAIL: {what}")
    print(f"ok  {what}")


def main(argv):
    global BASE, MODE
    args = [a for a in argv if not a.startswith("--")]
    requested = "auto"
    for a in argv:
        if a.startswith("--mode="):
            requested = a.split("=", 1)[1]
        elif a in ("--direct", "--proxied"):
            requested = a[2:]
    BASE = args[0].rstrip("/")
    MODE = detect_mode(BASE, requested)
    parts = urllib.parse.urlsplit(BASE)
    origin = f"{parts.scheme}://{parts.netloc}"
    print(f"target {BASE}  mode {MODE}")

    def as_client(ip, extra=None):
        """Headers for a request that should look like client `ip`. Proxied mode cannot choose its address."""
        h = {"origin": origin, **(extra or {})}
        if MODE == "direct":
            h["x-forwarded-for"] = ip
        return h

    status, body = call("GET", "/api/health")
    health = json.loads(body)
    ok(status == 200 and health["status"] == "ok", "health endpoint reachable")
    limit = health["limits_per_minute"]["write"]
    hops, header = health["proxy_hops"], health["client_ip_header"]
    print(f"     configuration: write limit {limit}/min, proxy hops {hops}, client ip header {header}, "
          f"seed on start {health['seed_on_start']}, ephemeral database {health['database_ephemeral']}")
    plan = probe_plan(MODE, limit, hops, header)
    ok(limit >= 15 or MODE == "direct", f"write limit {limit} leaves room for the functional checks in one shared bucket")

    if not health["seed_on_start"]:
        status, _ = call("POST", "/api/benchmark", {}, as_client("198.51.100.99"))
        ok(status in (200, 201), "benchmark seeded explicitly because seeding on start is off")

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
    same = as_client("198.51.100.7")
    status, body = call("POST", "/api/runs", {"scenario_id": "tool_response_injection"}, same)
    run = json.loads(body)
    ok(status == 201 and run["verification"]["verified"], "same-origin run accepted and verified")
    ok(run["summary"]["baseline"]["attack_succeeded"] and not run["summary"]["protected"]["attack_succeeded"]
       and run["summary"]["protected"]["task_completed"], "baseline compromised, protected blocked, task completed")

    status, _ = call("POST", "/api/runs", {"scenario_id": "benign_invoice"},
                     {**as_client("198.51.100.8"), "origin": "https://evil.example"})
    ok(status == 403, "cross-origin write rejected")

    status, body = call("POST", "/api/mcp/replay", {"scenario_id": "document_injection"}, same)
    ok(status == 200 and json.loads(body)["outcome"]["attack_succeeded"] is False, "MCP sandbox path works")

    # Malformed and hostile requests do not take the service down.
    ok(call("POST", "/api/verify", b"[" * 120000 + b"]" * 120000, as_client("192.0.2.60"))[0] in (400, 413),
       "deeply nested JSON rejected")
    ok(call("POST", "/api/verify", b"{not json", as_client("192.0.2.61"))[0] == 422, "invalid JSON rejected")
    ok(call("POST", "/api/runs", {"scenario_id": "x" * 10000}, as_client("192.0.2.62"))[0] == 422,
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
    ok(call("POST", "/api/live/runs", {"scenario_id": "document_injection"}, as_client("192.0.2.70"))[0] == 403,
       "live runs refused without an operator token")

    ok(call("GET", "/api/health")[0] == 200, "service still healthy after hostile requests")
    # Rate limiting, last, because it exhausts this client's bucket.
    def key(headers):
        return json.loads(call("GET", "/api/client-key", headers=headers)[1])["client_key_hash"]


    if MODE == "direct":
        k1 = key({"x-forwarded-for": "203.0.113.1"})
        k2 = key({"x-forwarded-for": "9.9.9.9, 203.0.113.1"})
        k3 = key({"x-forwarded-for": "203.0.113.2"})
        if plan["distinct_clients"]:
            ok(k1 == k2 != k3, "forged left-hand X-Forwarded-For entries do not change the client key; other clients differ")
        else:
            ok(k1 == k2 == k3, "this configuration ignores X-Forwarded-For, so all requests share one key")
    else:
        k1 = key({"x-forwarded-for": "203.0.113.1"})
        k2 = key({"x-forwarded-for": "9.9.9.9, 203.0.113.1"})
        k3 = key({})
        ok(k1 == k2 == k3, "forged X-Forwarded-For does not create new clients behind a real proxy")
        print(f"     client key from this machine: {k1}")
        print("     manual check: GET /api/client-key from a second network; the value must differ from the one above.")

    codes = []
    for _ in range(limit + 3):
        codes.append(call("POST", "/api/verify", {}, as_client("192.0.2.50"))[0])
        if codes[-1] == 429:
            break
    passed, why = judge_probe(codes, plan)
    ok(passed, f"per-client write limit enforced: {why}")
    if plan["distinct_clients"]:
        ok(call("POST", "/api/verify", {}, as_client("192.0.2.51"))[0] == 200, "other clients unaffected")

    ok(call("GET", "/api/health")[0] == 200, "service still healthy after the rate-limit probe")


if __name__ == "__main__":
    main(sys.argv[1:])
