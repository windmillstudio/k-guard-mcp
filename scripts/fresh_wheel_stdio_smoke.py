from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256, wheel_package_contract


PRIMARY_TOOLS = ("check_my_app", "continue_review", "start_review_before_ship")
REVIEW_POLL_ATTEMPTS = 24
REVIEW_POLL_WAIT_SECONDS = 4
# The smoke performs two complete reviews. Keep the outer watchdog longer than
# both bounded polling windows plus process startup/shutdown overhead.
STDIO_CONTRACT_TIMEOUT_SECONDS = (
    2 * REVIEW_POLL_ATTEMPTS * REVIEW_POLL_WAIT_SECONDS + 60
)
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_ERROR_CODES = {
    "installed wheel package does not match the release source package tree": "installed_package_tree_mismatch",
    "wheel package does not match the installed release package tree": "wheel_package_tree_mismatch",
    "wheel distribution identity does not match the installed package": "wheel_distribution_identity_mismatch",
    "MCP server name does not match the installed package": "server_name_mismatch",
    "MCP server version does not match the installed package": "server_version_mismatch",
    "primary MCP tools are missing or out of order": "primary_tool_contract_mismatch",
    "internal release helper is exposed as an MCP tool": "internal_tool_exposed",
    "primary output schema permits an incomplete envelope": "primary_output_schema_incomplete",
    "initial review did not reach a terminal state": "initial_review_timeout",
    "initial review did not complete": "initial_review_failed",
    "initial review receipt is not release eligible": "initial_receipt_ineligible",
    "release review did not reach a terminal state": "release_review_timeout",
    "release review worker did not complete": "release_review_failed",
    "release review is not bound to the initial source snapshot": "release_source_binding_failed",
    "Guardian terminal envelope is incomplete": "guardian_envelope_incomplete",
    "invalid review id did not fail closed": "invalid_review_id_not_fail_closed",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload(result: Any) -> dict[str, Any]:
    if result.isError is True or result.structuredContent is None or not result.content:
        raise RuntimeError("MCP tool returned an error or no structured content")
    text_payload = json.loads(result.content[0].text)
    if not isinstance(text_payload, dict) or text_payload != result.structuredContent:
        raise RuntimeError("MCP text and structured responses diverged")
    if not isinstance(text_payload.get("method"), str) or not isinstance(text_payload.get("experience"), dict):
        raise RuntimeError("MCP primary response envelope is incomplete")
    return text_payload


async def _run_stdio_contract(workspace: Path) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["K_GUARD_WORKSPACE_ROOT"] = str(workspace)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "k_guard_mcp.server"],
        env=environment,
        cwd=workspace,
    )
    calls = 0

    with anyio.fail_after(STDIO_CONTRACT_TIMEOUT_SECONDS):
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                if initialized.serverInfo.name != "K-Guard MCP":
                    raise RuntimeError("MCP server name does not match the installed package")
                if initialized.serverInfo.version != version("k-guard-mcp"):
                    raise RuntimeError("MCP server version does not match the installed package")
                listed = await session.list_tools()
                tool_names = [tool.name for tool in listed.tools]
                primary = {tool.name: tool for tool in listed.tools if tool.name in PRIMARY_TOOLS}
                if tuple(name for name in tool_names if name in PRIMARY_TOOLS) != PRIMARY_TOOLS:
                    raise RuntimeError("primary MCP tools are missing or out of order")
                if "review_before_ship" in tool_names:
                    raise RuntimeError("internal release helper is exposed as an MCP tool")
                for name in PRIMARY_TOOLS:
                    schema = primary[name].outputSchema or {}
                    if not {"method", "experience"}.issubset(set(schema.get("required", []))):
                        raise RuntimeError("primary output schema permits an incomplete envelope")

                async def invoke(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
                    nonlocal calls
                    result = await session.call_tool(name, arguments)
                    calls += 1
                    payload = _payload(result)
                    if str(workspace) in json.dumps(payload, ensure_ascii=False):
                        raise RuntimeError("MCP response exposed the raw workspace path")
                    return payload

                started = await invoke("check_my_app", {"path": ".", "include_flow": True})
                initial_review_id = str(started["review_job"]["review_id"])
                for _ in range(REVIEW_POLL_ATTEMPTS):
                    initial = await invoke(
                        "continue_review",
                        {"review_id": initial_review_id, "wait_seconds": REVIEW_POLL_WAIT_SECONDS},
                    )
                    if initial.get("review_job", {}).get("terminal") is True:
                        break
                else:
                    raise RuntimeError("initial review did not reach a terminal state")
                if initial.get("review_job", {}).get("state") != "completed":
                    raise RuntimeError("initial review did not complete")
                receipt = initial.get("review_receipt", {})
                if receipt.get("eligible_for_release_review") is not True or receipt.get("include_flow") is not True:
                    raise RuntimeError("initial review receipt is not release eligible")

                release_started = await invoke(
                    "start_review_before_ship",
                    {
                        "initial_review_id": initial_review_id,
                        "app_id": "fresh-wheel-stdio-smoke",
                        "business_purpose": "verify the packaged MCP release workflow",
                        "data_classes": "account,korean_pii",
                        "user_scope": "member,admin",
                        "scope_proof_ref": "owner-assertion:local-smoke",
                        "run_software_composition": False,
                    },
                )
                release_review_id = str(release_started["review_job"]["review_id"])
                for _ in range(REVIEW_POLL_ATTEMPTS):
                    release = await invoke(
                        "continue_review",
                        {"review_id": release_review_id, "wait_seconds": REVIEW_POLL_WAIT_SECONDS},
                    )
                    if release.get("review_job", {}).get("terminal") is True:
                        break
                else:
                    raise RuntimeError("release review did not reach a terminal state")
                if release.get("review_job", {}).get("state") != "completed":
                    raise RuntimeError("release review worker did not complete")
                binding = release.get("release_review_contract", {}).get("worker_source_binding", {})
                if (
                    release.get("release_review_contract", {}).get("source_snapshot_bound") is not True
                    or binding.get("worker_start_match") is not True
                    or binding.get("worker_end_match") is not True
                ):
                    raise RuntimeError("release review is not bound to the initial source snapshot")
                guardian = release.get("guardian_gate", {})
                if not isinstance(guardian.get("passed"), bool) or not isinstance(
                    guardian.get("canonical_release_authority"), bool
                ):
                    raise RuntimeError("Guardian terminal envelope is incomplete")

                invalid = await invoke(
                    "continue_review",
                    {"review_id": "missing-fresh-wheel-review", "wait_seconds": 0},
                )
                if invalid.get("experience", {}).get("verdict", {}).get("code") != "hold_incomplete":
                    raise RuntimeError("invalid review id did not fail closed")

    return {
        "server_name": initialized.serverInfo.name,
        "server_version": initialized.serverInfo.version,
        "tool_count": len(tool_names),
        "primary_tools": list(PRIMARY_TOOLS),
        "primary_output_schema_required": ["method", "experience"],
        "tool_call_count": calls,
        "initial_review_terminal": True,
        "initial_review_flow_included": True,
        "release_review_terminal": True,
        "release_source_snapshot_bound": True,
        "guardian_passed": guardian["passed"],
        "guardian_canonical_release_authority": guardian["canonical_release_authority"],
        "invalid_review_id_failed_closed": True,
        "text_structured_parity": True,
        "raw_workspace_path_returned": False,
    }


def build_report(wheel: Path, source_revision: str) -> dict[str, Any]:
    if not wheel.is_file() or wheel.suffix.casefold() != ".whl":
        raise ValueError("wheel must be an existing .whl file")
    if REVISION_RE.fullmatch(source_revision) is None:
        raise ValueError("source revision must be a full lowercase Git SHA")

    import k_guard_mcp

    installed_root = Path(k_guard_mcp.__file__).resolve().parent
    source_root = Path(__file__).resolve().parents[1] / "src" / "k_guard_mcp"
    installed_hash = package_tree_sha256(installed_root)
    source_hash = package_tree_sha256(source_root)
    wheel_contract = wheel_package_contract(wheel)
    package_version = version("k-guard-mcp")
    site_packages_loaded = any(part.casefold() == "site-packages" for part in installed_root.parts)
    if not site_packages_loaded or installed_hash != source_hash:
        raise RuntimeError("installed wheel package does not match the release source package tree")
    if wheel_contract["package_tree_sha256"] != installed_hash:
        raise RuntimeError("wheel package does not match the installed release package tree")
    if (
        str(wheel_contract["distribution"]).casefold().replace("_", "-") != "k-guard-mcp"
        or wheel_contract["version"] != package_version
    ):
        raise RuntimeError("wheel distribution identity does not match the installed package")

    with tempfile.TemporaryDirectory(prefix="k-guard-wheel-stdio-") as temporary:
        workspace = Path(temporary)
        (workspace / "app.ts").write_bytes(b"export function health() { return { ok: true }; }\n")
        contract = anyio.run(_run_stdio_contract, workspace)

    return {
        "schema": "k_guard_fresh_wheel_stdio_smoke.v3",
        "generated_at": datetime.now(UTC).isoformat(),
        "source_revision": source_revision,
        "package_version": package_version,
        "wheel_sha256": _sha256(wheel),
        "wheel_artifact": {
            "filename": wheel.name,
            "byte_count": wheel.stat().st_size,
            "sha256": _sha256(wheel),
            "package_tree_sha256": wheel_contract["package_tree_sha256"],
            "package_file_count": wheel_contract["package_file_count"],
            "distribution": wheel_contract["distribution"],
            "version": wheel_contract["version"],
            "artifact_role": "installed_smoke_input",
            "raw_returned": False,
        },
        "package_tree_hash_schema": TREE_HASH_SCHEMA,
        "source_package_tree_sha256": source_hash,
        "installed_package_tree_sha256": installed_hash,
        "site_packages_loaded": site_packages_loaded,
        "passed": True,
        "contract": contract,
        "claim_boundary": (
            "This proves the built wheel's stdio protocol and complete representative workflow against a local fixture. "
            "It is not a vendor UI certification, owned/partner field-accuracy result, or release SHIP verdict."
        ),
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the complete MCP workflow from an installed release wheel.")
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build_report(args.wheel.resolve(), args.source_revision)
    except Exception as exc:
        report = {
            "schema": "k_guard_fresh_wheel_stdio_smoke.v3",
            "source_revision": args.source_revision,
            "passed": False,
            "error_type": type(exc).__name__,
            "error_code": SAFE_ERROR_CODES.get(str(exc), "unclassified_smoke_failure"),
            "raw_returned": False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        print(json.dumps(report, ensure_ascii=False))
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({"passed": True, "tool_count": report["contract"]["tool_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
