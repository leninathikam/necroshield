"""Deployment configuration and tooling. Standard library only, so these run without the web stack."""

import importlib.util
import json
import re
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


smoke = _load("container_smoke", ROOT / ".github/scripts/container_smoke.py")
render_env = _load("render_env", ROOT / ".github/scripts/render_env.py")
xff_proxy = _load("xff_proxy", ROOT / ".github/scripts/xff_proxy.py")


# --- smoke test is configuration aware -------------------------------------------------------------

def test_mode_detection():
    assert smoke.detect_mode("http://127.0.0.1:10000") == "direct"
    assert smoke.detect_mode("http://localhost:8000") == "direct"
    assert smoke.detect_mode("https://necroshield.onrender.com") == "proxied"
    assert smoke.detect_mode("http://example.test") == "proxied"
    assert smoke.detect_mode("https://necroshield.onrender.com", "direct") == "direct"
    assert smoke.detect_mode("http://127.0.0.1:1", "proxied") == "proxied"


def test_direct_probe_expects_exactly_the_configured_limit():
    for limit in (5, 30, 60):
        plan = smoke.probe_plan("direct", limit, 1, False)
        assert plan["distinct_clients"] and plan["exact"]
        assert smoke.judge_probe([200] * limit + [429], plan)[0]
        assert not smoke.judge_probe([200] * (limit - 1) + [429], plan)[0]
        assert not smoke.judge_probe([200] * (limit + 1) + [429], plan)[0]


def test_the_probe_does_not_assume_a_limit_of_five():
    plan30 = smoke.probe_plan("direct", 30, 1, False)
    assert not smoke.judge_probe([200] * 5 + [429], plan30)[0]  # a hard-coded 5 would wrongly pass this
    assert smoke.judge_probe([200] * 30 + [429], plan30)[0]


def test_proxied_probe_allows_earlier_429_because_the_bucket_is_shared():
    plan = smoke.probe_plan("proxied", 30, 1, False)
    assert not plan["distinct_clients"] and not plan["exact"]
    assert smoke.judge_probe([200] * 12 + [429], plan)[0]
    assert not smoke.judge_probe([200] * 31 + [429], plan)[0]
    assert not smoke.judge_probe([200] * 33, plan)[0]  # never limited
    assert not smoke.judge_probe([429], plan)[0]


def test_forging_only_creates_clients_when_the_app_trusts_the_header_and_nothing_sits_in_front():
    assert not smoke.probe_plan("direct", 30, 0, False)["distinct_clients"]
    assert not smoke.probe_plan("direct", 30, 1, True)["distinct_clients"]
    assert not smoke.probe_plan("proxied", 30, 1, False)["distinct_clients"]


def test_unexpected_status_before_the_limit_fails():
    plan = smoke.probe_plan("direct", 3, 1, False)
    assert not smoke.judge_probe([200, 500, 200, 429], plan)[0]


# --- render.yaml and render_env ---------------------------------------------------------------------

def _blueprint():
    return render_env.parse_env_vars((ROOT / "render.yaml").read_text())


def test_blueprint_is_the_free_plan_with_ephemeral_database():
    text = (ROOT / "render.yaml").read_text()
    env, skipped = _blueprint()
    assert re.search(r"^\s*plan: free\s*$", text, re.M) and "disk:" not in text
    assert env["NECROSHIELD_DB"] == "/tmp/necroshield.db"
    assert env["NECROSHIELD_SEED_ON_START"] == "1" and env["NECROSHIELD_PROXY_HOPS"] == "1"
    assert env["NECROSHIELD_WRITE_LIMIT"] == "30"
    assert not any(k.startswith("NECROSHIELD_LLM") or "TOKEN" in k or "SIGNING" in k for k in env)
    assert skipped == []  # nothing in the blueprint prompts for a value at creation


def test_blueprint_does_not_prompt_for_allowed_origins():
    assert "NECROSHIELD_ALLOWED_ORIGINS" not in (ROOT / "render.yaml").read_text().replace("NECROSHIELD_ALLOWED_ORIGINS in the dashboard", "")


def test_render_env_flags_and_strictness():
    env, skipped = render_env.parse_env_vars(
        "services:\n  - type: web\n    envVars:\n      - key: A\n        value: \"1\"   # note\n"
        "      - key: B\n        sync: false\n      - key: C\n        value: x y\nother: 1\n")
    assert env == {"A": "1", "C": "x y"} and skipped == ["B"]
    try:
        render_env.parse_env_vars("envVars:\n  - key: A\n    value: 1\n  - key: A\n    value: 2\n")
    except ValueError:
        pass
    else:
        raise AssertionError("duplicates must be rejected")


def test_ci_uses_the_blueprint_environment_and_both_smoke_modes():
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "render_env.py render.yaml" in ci
    assert "container_smoke.py http://127.0.0.1:10001 --direct" in ci
    assert "container_smoke.py http://127.0.0.1:10002 --proxied" in ci
    assert "xff_proxy.py 10002" in ci


# --- deployment document ----------------------------------------------------------------------------

def _sections():
    text = (ROOT / "docs/deployment.md").read_text()
    free = re.search(r"<!-- free:start -->(.*?)<!-- free:end -->", text, re.S)
    paid = re.search(r"<!-- paid:start -->(.*?)<!-- paid:end -->", text, re.S)
    assert free and paid, "deployment.md must delimit the free and paid parts"
    return free.group(1), paid.group(1)


def test_free_instructions_use_tmp_and_never_the_disk_path():
    free, paid = _sections()
    assert "/tmp/necroshield.db" in free
    assert "/data" not in free
    assert "reset-store" not in free  # the reset command needs a shell; the free plan resets by restart or redeploy


def test_paid_instructions_use_the_disk_path():
    _free, paid = _sections()
    assert "/data/necroshield.db" in paid and "reset-store" in paid


def test_deployment_doc_covers_the_operational_facts():
    text = (ROOT / "docs/deployment.md").read_text().lower()
    for phrase in ("cold start", "15 minutes", "reseed", "proxy_hops", "unverified", "auto-deploy", "client-key",
                   "allowed_origins", "write limit of 30"):
        assert phrase in text, phrase


# --- the proxy helper -------------------------------------------------------------------------------

def test_xff_append():
    assert xff_proxy.append_forwarded_for(None, "1.2.3.4") == "1.2.3.4"
    assert xff_proxy.append_forwarded_for("9.9.9.9", "1.2.3.4") == "9.9.9.9, 1.2.3.4"


def test_proxy_appends_the_real_client_address_and_forwards_host_and_body():
    seen = {}

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["content-length"]))
            seen.update(xff=self.headers["x-forwarded-for"], host=self.headers["host"], body=body)
            out = b'{"ok": true}'
            self.send_response(201)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *_a):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    proxy = xff_proxy.make_server(0, f"http://127.0.0.1:{upstream.server_address[1]}")
    for srv in (upstream, proxy):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{proxy.server_address[1]}/x", data=b'{"a":1}', method="POST",
                                     headers={"X-Forwarded-For": "6.6.6.6"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 201 and json.loads(r.read()) == {"ok": True}
    finally:
        proxy.shutdown()
        upstream.shutdown()
    assert seen["xff"] == "6.6.6.6, 127.0.0.1"  # forged entry kept on the left, real address appended
    assert seen["body"] == b'{"a":1}' and seen["host"].startswith("127.0.0.1:")
