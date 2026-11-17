import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from necroshield.engine import execute_pair
from necroshield.scenarios import DOCUMENT_INJECTION
from necroshield.storage import Repository


def test_official_sdk_stdio_gateway_and_readonly_evidence_inspector(tmp_path):
    repository = Repository(f"sqlite:///{tmp_path / 'necroshield.db'}")
    pair = execute_pair(DOCUMENT_INJECTION)
    repository.save(pair)
    repository.close()

    async def exercise():
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "VIRTUAL_ENV"}}
        environment["NECROSHIELD_DATA_DIR"] = str(tmp_path)
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "necroshield.mcp_server"],
            cwd=str(Path(__file__).resolve().parents[1]), env=environment)
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                listed = await session.list_tools()
                assert {tool.name for tool in listed.tools} == {
                    "list_benchmarks", "inspect_run", "read_synthetic_invoice", "sandbox_tool_call"}
                denied = await session.call_tool("sandbox_tool_call", {"tool": "sink.send", "arguments": {
                    "destination": "local://sink", "payload": "synthetic-inert"}})
                assert not denied.isError
                data = json.loads(denied.content[0].text)
                assert data["decision"] == "deny"
                assert data["executed"] is False
                assert data["effects"]["sink_received"] is False
                assert data["effects"]["executed_tools"] == []
                allowed = await session.call_tool("sandbox_tool_call", {"tool": "document.read", "arguments": {
                    "document_id": "doc://invoice-001"}})
                assert json.loads(allowed.content[0].text)["executed"] is True
                result = await session.call_tool("inspect_run", {"pair_id": pair.id})
                evidence = json.loads(result.content[0].text)
                assert evidence["id"] == pair.id
                assert evidence["evidence"]["baseline_chain_valid"]
                assert "SYNTHETIC-SECRET" not in str(evidence)
                invalid = await session.call_tool("inspect_run", {"pair_id": "../../file"})
                assert invalid.isError
    asyncio.run(exercise())
