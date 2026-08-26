#!/usr/bin/env python3
"""Exercise the installed CLI and a real bounded MCP stdio initialization."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from k_guard_mcp import __version__


REQUIRED_PRIMARY_TOOLS = {"check_my_app", "continue_review", "start_review_before_ship"}
DUMMY_NAME = "홍길동"
DUMMY_PHONE = "010-9876-5432"
DUMMY_SECRET = "sk-thisisaverylongfakeapikey321"


async def _initialize_installed_server() -> dict[str, object]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONIOENCODING"] = "utf-8"
    with tempfile.TemporaryDirectory(prefix="k-guard-readme-smoke-") as temporary:
        workspace = Path(temporary)
        (workspace / "app.py").write_text("def health():\n    return {'ok': True}\n", encoding="utf-8")
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "k_guard_mcp.server"],
            cwd=workspace,
            env=environment,
        )
        with anyio.fail_after(30):
            async with stdio_client(parameters) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    listed = await session.list_tools()
                    scanned = await session.call_tool(
                        "scan_text",
                        {"text": f"name: {DUMMY_NAME} phone={DUMMY_PHONE} token={DUMMY_SECRET}"},
                    )
    names = {tool.name for tool in listed.tools}
    missing = sorted(REQUIRED_PRIMARY_TOOLS - names)
    if missing:
        raise RuntimeError(f"installed MCP server is missing primary tools: {missing}")
    if initialized.serverInfo.version != __version__:
        raise RuntimeError(
            "installed MCP server advertised the SDK version instead of the K-Guard package version"
        )
    if not scanned.content or not hasattr(scanned.content[0], "text"):
        raise RuntimeError("installed MCP scan_text returned no text payload")
    rendered = str(scanned.content[0].text)
    if any(raw in rendered for raw in (DUMMY_NAME, DUMMY_PHONE, DUMMY_SECRET)):
        raise RuntimeError("installed MCP scan_text exposed a raw dummy sensitive value")
    payload = json.loads(rendered)
    if int(payload.get("summary", {}).get("critical", 0)) < 1:
        raise RuntimeError("installed MCP scan_text did not detect the dummy secret")
    return {
        "passed": True,
        "transport": "stdio",
        "initialized": True,
        "server_version": initialized.serverInfo.version,
        "tool_count": len(names),
        "required_primary_tools": sorted(REQUIRED_PRIMARY_TOOLS),
        "scan_text_called": True,
        "scan_text_raw_free": True,
    }


def main() -> int:
    from k_guard_mcp import server

    server_path = Path(server.__file__).resolve()
    if not any(part.casefold() == "site-packages" for part in server_path.parts):
        raise RuntimeError("packaging smoke imported K-Guard from the checkout instead of the fresh environment")
    report = anyio.run(_initialize_installed_server)
    report["installed_from_site_packages"] = True
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
