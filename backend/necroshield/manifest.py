"""MCP trust inspector: tool manifests, hashes, drift detection, and the activation gate.

Scope. This inspects ONLY the NecroShield sandbox's own synthetic tools. No external MCP server is
contacted, scanned, or attacked. The "observed" manifest is what the sandbox's MCP server actually
advertises through an official-SDK client session; the "approved" manifest is a reviewed file in the
repository (`approved_manifest.json`).

MCP advertises names, descriptions, and input schemas, but not capabilities. The capability table
below is NecroShield's own annotation of what each synthetic tool can do. Capability drift is therefore
detectable only in a manifest that carries capabilities, never in a bare MCP listing; the drift examples
say which kind each one is.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from .contracts import canonical_json
from .tools import TOOLS

MANIFEST_FORMAT = "necroshield.mcp-manifest/1"
APPROVED_PATH = Path(__file__).with_name("approved_manifest.json")

CAPABILITIES: dict[str, dict[str, Any]] = {
    "read_document": {"effects": ["read:document"], "egress": "none", "sensitivity": "synthetic document"},
    "get_customer_record": {"effects": ["read:customer-record"], "egress": "none", "sensitivity": "synthetic personal data"},
    "write_report": {"effects": ["write:report-store"], "egress": "none", "sensitivity": "synthetic report"},
    "send_message": {"effects": ["write:in-memory-sink"], "egress": "synthetic sink only (*.invalid)", "sensitivity": "synthetic message"},
    "read_memory": {"effects": ["read:agent-memory"], "egress": "none", "sensitivity": "synthetic memory"},
    "write_memory": {"effects": ["write:agent-memory"], "egress": "none", "sensitivity": "synthetic memory"},
}
UNDECLARED = {"effects": ["UNDECLARED"], "egress": "UNDECLARED", "sensitivity": "UNDECLARED"}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def canonical_schema(value: Any) -> Any:
    """The full input schema with only `title` keys removed (the SDK generates them from function names;
    they carry no meaning). Everything else counts: descriptions, enums, patterns, lengths, formats,
    defaults, and additionalProperties are all ways to change what a model is told or allowed to send."""
    if isinstance(value, dict):
        return {k: canonical_schema(v) for k, v in sorted(value.items()) if k != "title"}
    if isinstance(value, list):
        return [canonical_schema(v) for v in value]
    return value


def normalize_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """A short, human-readable summary: {properties: {name: 'string' | 'string?'}, required: [...]}.
    For display and for the headline diff only; the hash covers the full canonical schema."""
    props: dict[str, str] = {}
    for name, spec in (schema.get("properties") or {}).items():
        raw = spec.get("type")
        kinds = (list(raw) if isinstance(raw, list) else [raw]) if raw is not None else [k.get("type", "?") for k in spec.get("anyOf", [])]
        base = "|".join(sorted(k for k in kinds if k != "null")) or "?"
        props[name] = base + ("?" if "null" in kinds else "")
    return {"properties": dict(sorted(props.items())), "required": sorted(schema.get("required") or [])}


def tool_entry(name: str, description: str, schema: dict[str, Any], capabilities: dict[str, Any] | None = None,
               annotations: dict[str, Any] | None = None) -> dict[str, Any]:
    entry = {"name": name, "description": description, "input": normalize_schema(schema), "schema": canonical_schema(schema),
             "annotations": annotations or {},
             "capabilities": capabilities if capabilities is not None else CAPABILITIES.get(name, UNDECLARED)}
    return {**entry, "hash": _sha(entry)}


def build_manifest(entries: list[dict[str, Any]]) -> dict[str, Any]:
    tools = sorted(entries, key=lambda t: t["name"])
    return {"format": MANIFEST_FORMAT, "tools": tools, "digest": _sha([t["hash"] for t in tools])}


def declared_manifest() -> dict[str, Any]:
    """What the code says the sandbox exposes, built from the tool specs (not from a running server)."""
    entries = []
    for spec in TOOLS.values():
        # Mirrors the schema FastMCP derives from the handler signatures (titles are dropped by canonical_schema).
        schema = {"type": "object",
                  "properties": {**{a: {"type": "string"} for a in spec.required},
                                 **{a: {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None} for a in spec.optional}},
                  "required": list(spec.required)}
        entries.append(tool_entry(spec.name, spec.description, schema))
    return build_manifest(entries)


def manifest_from_listing(tools: list[Any]) -> dict[str, Any]:
    """Build the observed manifest from an MCP `tools/list` result (objects with name, description,
    inputSchema)."""
    def annotations(t: Any) -> dict[str, Any]:
        raw = getattr(t, "annotations", None)
        return raw.model_dump(exclude_none=True) if raw is not None and hasattr(raw, "model_dump") else dict(raw or {})

    return build_manifest([tool_entry(t.name, t.description or "", t.inputSchema or {}, None, annotations(t)) for t in tools])


def load_approved() -> dict[str, Any]:
    return json.loads(APPROVED_PATH.read_text(encoding="utf-8"))


# --- drift --------------------------------------------------------------------------------------

def _change(tool: str, kind: str, severity: str, summary: str, before: Any = None, after: Any = None) -> dict[str, Any]:
    return {"tool": tool, "kind": kind, "severity": severity, "summary": summary, "before": before, "after": after}


def _short(value: Any) -> str:
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _raw_changes(before: Any, after: Any, path: str = "$"):
    """Yield (path, before, after) for every leaf at which two canonical schemas differ."""
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            yield from _raw_changes(before.get(key), after.get(key), f"{path}.{key}")
    elif before != after:
        yield path, before, after


def diff(approved: dict[str, Any], observed: dict[str, Any]) -> list[dict[str, Any]]:
    """Human-readable differences. `severity`: escalation (new power or new surface), change, reduction."""
    a = {t["name"]: t for t in approved["tools"]}
    o = {t["name"]: t for t in observed["tools"]}
    out: list[dict[str, Any]] = []
    for name in sorted(set(o) - set(a)):
        caps = o[name]["capabilities"]
        out.append(_change(name, "tool_added", "escalation", f"New tool '{name}' appeared with effects {caps['effects']} and egress '{caps['egress']}'.", None, o[name]))
    for name in sorted(set(a) - set(o)):
        out.append(_change(name, "tool_removed", "reduction", f"Tool '{name}' is no longer offered.", a[name], None))
    for name in sorted(set(a) & set(o)):
        before, after = a[name], o[name]
        if before["hash"] == after["hash"]:
            continue
        if before["description"] != after["description"]:
            lines = [ln for ln in difflib.unified_diff(before["description"].split(". "), after["description"].split(". "), lineterm="", n=0)
                     if not ln.startswith(("---", "+++", "@@"))]
            out.append(_change(name, "description_changed", "escalation" if len(after["description"]) > len(before["description"]) + 40 else "change",
                               f"The description of '{name}' changed (descriptions are read by models, so this is an instruction channel).",
                               before["description"], after["description"]) | {"diff": lines})
        bi, ai = before["input"], after["input"]
        for prop in sorted(set(ai["properties"]) - set(bi["properties"])):
            out.append(_change(name, "argument_added", "escalation", f"'{name}' gained an argument '{prop}' ({ai['properties'][prop]}).", None, ai["properties"][prop]))
        for prop in sorted(set(bi["properties"]) - set(ai["properties"])):
            out.append(_change(name, "argument_removed", "reduction", f"'{name}' lost the argument '{prop}'.", bi["properties"][prop], None))
        for prop in sorted(set(bi["properties"]) & set(ai["properties"])):
            if bi["properties"][prop] != ai["properties"][prop]:
                out.append(_change(name, "argument_type_changed", "escalation", f"'{name}' argument '{prop}' changed type: {bi['properties'][prop]} -> {ai['properties'][prop]}.",
                                   bi["properties"][prop], ai["properties"][prop]))
        if bi["required"] != ai["required"]:
            out.append(_change(name, "required_changed", "change", f"Required arguments of '{name}' changed: {bi['required']} -> {ai['required']}.", bi["required"], ai["required"]))
        if bi == ai and before["schema"] != after["schema"]:
            for path, was, now in _raw_changes(before["schema"], after["schema"]):
                risky = any(part in path for part in ("description", "enum", "pattern", "additionalProperties", "maxLength", "format", "const", "anyOf", "oneOf", "allOf"))
                out.append(_change(name, "schema_detail_changed", "escalation" if risky else "change",
                                   f"'{name}' input schema changed at {path}: {_short(was)} -> {_short(now)}.", was, now))
        if before["annotations"] != after["annotations"]:
            out.append(_change(name, "annotations_changed", "escalation", f"Behaviour hints of '{name}' changed: {before['annotations']} -> {after['annotations']}.",
                               before["annotations"], after["annotations"]))
        bc, ac = before["capabilities"], after["capabilities"]
        for effect in sorted(set(ac["effects"]) - set(bc["effects"])):
            out.append(_change(name, "capability_added", "escalation", f"'{name}' gained the effect '{effect}'.", bc["effects"], ac["effects"]))
        for effect in sorted(set(bc["effects"]) - set(ac["effects"])):
            out.append(_change(name, "capability_removed", "reduction", f"'{name}' lost the effect '{effect}'.", bc["effects"], ac["effects"]))
        if bc["egress"] != ac["egress"]:
            out.append(_change(name, "egress_changed", "escalation", f"Egress of '{name}' changed: '{bc['egress']}' -> '{ac['egress']}'.", bc["egress"], ac["egress"]))
    return out


def gate(approved: dict[str, Any], observed: dict[str, Any], approved_digests: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Activation decision. Activation needs the approved digest, or an explicit approval of this exact
    observed digest. A different drift needs its own approval: an approval never carries over."""
    changes = diff(approved, observed)
    if observed["digest"] == approved["digest"]:
        return {"activate": True, "status": "matches the approved manifest", "changes": []}
    escalations = sum(c["severity"] == "escalation" for c in changes)
    if observed["digest"] in approved_digests:
        return {"activate": True, "status": "drift approved for this exact manifest digest only", "changes": changes}
    return {"activate": False, "status": f"drift detected: activation refused ({len(changes)} changes, {escalations} escalations)",
            "changes": changes}


# --- synthetic drifted listings (served by the real MCP sandbox, see mcp_server.build_sandbox) ---

DRIFT_EXAMPLES: dict[str, str] = {
    "benign_description_edit": "A harmless-looking wording change to a tool description (still needs review).",
    "description_injection": "A tool description that now carries an instruction aimed at the model (inert text).",
    "schema_widened": "send_message gains an optional 'cc' argument.",
    "tool_added": "A new tool 'export_all_records' appears.",
    "tool_removed": "write_report disappears.",
}

# Capability drift cannot be advertised over MCP, so it exists only as a manifest-level mutation.
def _capability_escalation(manifest: dict[str, Any]) -> dict[str, Any]:
    tools = []
    for t in manifest["tools"]:
        if t["name"] == "send_message":
            caps = {**t["capabilities"], "effects": [*t["capabilities"]["effects"], "network:outbound"], "egress": "any host"}
            t = tool_entry(t["name"], t["description"], t["schema"], caps, t["annotations"])
        tools.append(t)
    return build_manifest(tools)


MANIFEST_MUTATIONS: dict[str, tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]] = {
    "capability_escalation": ("send_message is annotated with outbound network access (manifest-level; MCP does not advertise capabilities).", _capability_escalation),
}
