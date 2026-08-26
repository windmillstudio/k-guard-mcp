from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

try:
    from supervisor_executable_resolution import resolve_supervisor_executable, resolve_supervisor_executables
except ModuleNotFoundError:
    from scripts.supervisor_executable_resolution import resolve_supervisor_executable, resolve_supervisor_executables


SCHEMA = "k_guard_external_supervisor_health_receipt.v2"
PREVIOUS_SCHEMA = "k_guard_external_supervisor_health_receipt.v1"
HEALTH_CHECK_PROFILE = "source_free_terminal_json_v1"
EXPECTED_TERMINAL_DECISION = {
    "approval": False,
    "scope": "no-tool-health-check",
    "status": "HEALTHY",
}
LANES: tuple[dict[str, str], ...] = (
    {
        "provider": "claude",
        "model": "claude-opus-5",
        "invocation_profile": "claude_print_source_free_plan_v2",
    },
    {
        "provider": "grok",
        "model": "grok-4.6",
        "invocation_profile": "grok_single_no_tool_plan_v2",
    },
)
PREVIOUS_LANES: tuple[dict[str, str], ...] = (
    {
        "provider": "claude",
        "model": "claude-opus-4-8",
        "invocation_profile": "claude_print_source_free_plan_v1",
    },
    {
        "provider": "grok",
        "model": "grok-4.5",
        "invocation_profile": "grok_single_no_tool_plan_v1",
    },
    {
        "provider": "glm",
        "model": "cline-pass/glm-5.2",
        "invocation_profile": "cline_plan_no_tool_v1",
    },
)
BLOCKED_REASONS = {
    "BLOCKED_AUTH",
    "BLOCKED_PROVIDER",
    "BLOCKED_RATE_LIMIT",
    "BLOCKED_TIMEOUT",
}
Runner = Callable[..., subprocess.CompletedProcess[str]]


def lanes_for_schema(schema: object) -> tuple[dict[str, str], ...]:
    if schema == SCHEMA:
        return LANES
    if schema == PREVIOUS_SCHEMA:
        return PREVIOUS_LANES
    raise ValueError("health receipt schema is invalid")


def _model_for_provider(provider: str) -> str:
    for lane in (*LANES, *PREVIOUS_LANES):
        if lane["provider"] == provider:
            return lane["model"]
    raise ValueError("supervisor provider is invalid")


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _health_prompt() -> str:
    return "Return exactly this JSON object and nothing else: " + json.dumps(
        EXPECTED_TERMINAL_DECISION,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _glm_health_system_prompt() -> str:
    return (
        "This is a source-free health check. Return exactly this JSON object and nothing else: "
        + json.dumps(EXPECTED_TERMINAL_DECISION, ensure_ascii=False, separators=(",", ":"))
        + " Do not use tools, make a plan, or explain."
    )


def build_command(provider: str, executable: str, *, timeout_seconds: int) -> list[str]:
    if not executable:
        raise ValueError("supervisor executable is required")
    executable = resolve_supervisor_executable(executable, provider=provider)
    prompt = _health_prompt()
    if provider == "claude":
        return [
            executable,
            "--print",
            "--model",
            _model_for_provider(provider),
            "--effort",
            "max",
            "--output-format",
            "json",
            "--no-session-persistence",
            "--permission-mode",
            "plan",
            prompt,
        ]
    if provider == "grok":
        return [
            executable,
            "--single",
            prompt,
            "--model",
            _model_for_provider(provider),
            "--output-format",
            "json",
            "--disable-web-search",
            "--no-subagents",
            "--no-memory",
            "--no-plan",
            "--reasoning-effort",
            "xhigh",
            "--permission-mode",
            "plan",
            "--tools",
            "",
            "--max-turns",
            "1",
        ]
    if provider == "glm":
        return [
            executable,
            "--json",
            "--auto-approve",
            "false",
            "--plan",
            "--system",
            _glm_health_system_prompt(),
            "--model",
            _model_for_provider(provider),
            "--thinking",
            "high",
            "--timeout",
            str(timeout_seconds),
            prompt,
        ]
    raise ValueError("supervisor provider is invalid")


def _parse_object(value: object) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _terminal_decision(provider: str, stdout: str) -> dict[str, Any] | None:
    if provider in {"claude", "grok"}:
        envelope = _parse_object(stdout)
        if envelope is None:
            return None
        key = "result" if provider == "claude" else "text"
        return _parse_object(envelope.get(key))
    if provider == "glm":
        terminal_values: list[str] = []
        for line in stdout.splitlines():
            event = _parse_object(line)
            if event is None or event.get("type") != "run_result":
                continue
            value = event.get("text")
            if isinstance(value, str):
                terminal_values.append(value)
        if len(terminal_values) != 1:
            return None
        return _parse_object(terminal_values[0])
    raise ValueError("supervisor provider is invalid")


def _blocked_reason(stdout: str, stderr: str) -> str:
    text = (stdout + "\n" + stderr).lower()
    if any(token in text for token in ("rate limit", "rate_limit", "quota", "too many requests", " 429")):
        return "BLOCKED_RATE_LIMIT"
    if any(
        token in text
        for token in (
            "not logged",
            "login",
            "authentication",
            "not authenticated",
            "auth required",
            "unauthorized",
            "forbidden",
            "api key",
            "credential",
        )
    ):
        return "BLOCKED_AUTH"
    return "BLOCKED_PROVIDER"


def _run_lane(
    lane: Mapping[str, str],
    executable: str,
    *,
    timeout_seconds: int,
    working_directory: Path,
    runner: Runner,
) -> dict[str, Any]:
    provider = lane["provider"]
    try:
        completed = runner(
            build_command(provider, executable, timeout_seconds=timeout_seconds),
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _blocked_lane(lane, "BLOCKED_TIMEOUT")
    except OSError:
        return _blocked_lane(lane, "BLOCKED_PROVIDER")

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    decision = _terminal_decision(provider, stdout) if completed.returncode == 0 else None
    if decision == EXPECTED_TERMINAL_DECISION:
        return {
            "provider": provider,
            "model": lane["model"],
            "invocation_profile": lane["invocation_profile"],
            "status": "HEALTHY",
            "blocked_reason": None,
            "exit_code": 0,
            "terminal_response_valid": True,
            "raw_returned": False,
        }
    return _blocked_lane(
        lane,
        _blocked_reason(stdout, stderr),
        exit_code=completed.returncode,
        terminal_response_valid=decision is not None,
    )


def _blocked_lane(
    lane: Mapping[str, str],
    reason: str,
    *,
    exit_code: int | None = None,
    terminal_response_valid: bool = False,
) -> dict[str, Any]:
    if reason not in BLOCKED_REASONS:
        raise ValueError("supervisor blocked reason is invalid")
    return {
        "provider": lane["provider"],
        "model": lane["model"],
        "invocation_profile": lane["invocation_profile"],
        "status": "BLOCKED",
        "blocked_reason": reason,
        "exit_code": exit_code,
        "terminal_response_valid": terminal_response_valid,
        "raw_returned": False,
    }


def health_measurement_fingerprint(receipt: Mapping[str, Any]) -> str:
    lanes = receipt.get("lanes")
    if not isinstance(lanes, list):
        raise ValueError("health receipt lanes are invalid")
    projection = {
        "schema": receipt.get("schema"),
        "health_check_profile": receipt.get("health_check_profile"),
        "purpose": receipt.get("purpose"),
        "approval": receipt.get("approval"),
        "review_receipt_eligible": receipt.get("review_receipt_eligible"),
        "all_required_lanes_healthy": receipt.get("all_required_lanes_healthy"),
        "overall_status": receipt.get("overall_status"),
        "expected_terminal_decision": receipt.get("expected_terminal_decision"),
        "lanes": [
            {
                "provider": lane.get("provider"),
                "model": lane.get("model"),
                "invocation_profile": lane.get("invocation_profile"),
                "status": lane.get("status"),
                "blocked_reason": lane.get("blocked_reason"),
                "exit_code": lane.get("exit_code"),
                "terminal_response_valid": lane.get("terminal_response_valid"),
                "raw_returned": lane.get("raw_returned"),
            }
            for lane in lanes
            if isinstance(lane, Mapping)
        ],
        "claim_boundary": receipt.get("claim_boundary"),
        "raw_returned": receipt.get("raw_returned"),
    }
    if len(projection["lanes"]) != len(lanes):
        raise ValueError("health receipt lane is invalid")
    return sha256_bytes(projection)


def run_health_check(
    executables: Mapping[str, str],
    *,
    timeout_seconds: int = 120,
    runner: Runner = subprocess.run,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if timeout_seconds < 1 or timeout_seconds > 600:
        raise ValueError("timeout_seconds must be between 1 and 600")
    missing = {lane["provider"] for lane in LANES} - set(executables)
    if missing:
        raise ValueError("supervisor executable mapping is incomplete")
    resolved_executables = resolve_supervisor_executables(
        {lane["provider"]: executables[lane["provider"]] for lane in LANES}
    )

    with tempfile.TemporaryDirectory(prefix="k-guard-supervisor-health-") as temporary:
        working_directory = Path(temporary)
        lanes = [
            _run_lane(
                lane,
                resolved_executables[lane["provider"]],
                timeout_seconds=timeout_seconds,
                working_directory=working_directory,
                runner=runner,
            )
            for lane in LANES
        ]
    all_healthy = all(lane["status"] == "HEALTHY" for lane in lanes)
    receipt = {
        "schema": SCHEMA,
        "health_check_profile": HEALTH_CHECK_PROFILE,
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "purpose": "external_supervisor_availability_only",
        "approval": False,
        "review_receipt_eligible": False,
        "all_required_lanes_healthy": all_healthy,
        "overall_status": "HEALTHY" if all_healthy else "BLOCKED",
        "expected_terminal_decision": EXPECTED_TERMINAL_DECISION,
        "lanes": lanes,
        "claim_boundary": {
            "does_not_approve_code": True,
            "does_not_approve_field_fix": True,
            "does_not_approve_release": True,
            "does_not_prove_model_direct_file_access": True,
            "does_not_replace_supervisor_review_receipts": True,
            "raw_returned": False,
        },
        "raw_returned": False,
    }
    receipt["measurement_fingerprint_sha256"] = health_measurement_fingerprint(receipt)
    return receipt


def write_receipt(output: Path, receipt: Mapping[str, Any]) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite an existing health receipt")
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(dict(receipt))
    try:
        with output.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing to overwrite an existing health receipt") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify external supervisor availability without creating a review or approval receipt."
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--claude-exe", default=os.environ.get("K_GUARD_CLAUDE_EXE", "claude"))
    parser.add_argument("--grok-exe", default=os.environ.get("K_GUARD_GROK_EXE", "grok"))
    args = parser.parse_args(argv)

    receipt = run_health_check(
        {"claude": args.claude_exe, "grok": args.grok_exe},
        timeout_seconds=args.timeout_seconds,
    )
    write_receipt(args.output, receipt)
    print(
        json.dumps(
            {
                "schema": receipt["schema"],
                "all_required_lanes_healthy": receipt["all_required_lanes_healthy"],
                "overall_status": receipt["overall_status"],
                "output": str(args.output.resolve()),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if receipt["all_required_lanes_healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
