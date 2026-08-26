from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

try:
    import execute_supervisor_review as review
except ModuleNotFoundError:
    from scripts import execute_supervisor_review as review

from k_guard_mcp.supervisor_reviews import REQUIRED_MODELS, canonical_json_bytes, sha256_bytes  # noqa: E402


SCHEMA = "k_guard_supervisor_long_packet_transport_probe.v1"
PACKET_SCHEMA = "k_guard_supervisor_long_packet_transport_packet.v1"
FIELD_ID = "p8.2b.windows-native-supervisor-transport"
SHIM_COMMAND_LINE_LIMIT = 8_191
NATIVE_COMMAND_LINE_LIMIT = 32_767
DEFAULT_PADDING_BYTES = 12_000
MIN_PADDING_BYTES = 8_192
MAX_PADDING_BYTES = 24_000
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _write_canonical_new(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or _is_within(path, REPOSITORY_ROOT):
        raise ValueError("transport probe output must be new and outside the repository")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(payload)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("transport probe output must be new and outside the repository") from exc


def _capture_target(repo_root: Path) -> dict[str, str]:
    module_path = repo_root / "scripts" / "capture_supervisor_target.py"
    spec = importlib.util.spec_from_file_location("capture_supervisor_target", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("target capture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.capture_target(repo_root)


def _direct_file(repo_root: Path, value: str) -> str:
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError("transport probe direct file must be repository-relative")
    resolved = (repo_root / candidate).resolve(strict=True)
    if not _is_within(resolved, repo_root) or not resolved.is_file() or resolved.is_symlink():
        raise ValueError("transport probe direct file is invalid")
    return resolved.relative_to(repo_root).as_posix()


def _packet(*, target: Mapping[str, str], direct_file: str, padding_bytes: int) -> dict[str, Any]:
    if padding_bytes < MIN_PADDING_BYTES or padding_bytes > MAX_PADDING_BYTES:
        raise ValueError("transport probe padding is outside the preregistered range")
    return {
        "schema": PACKET_SCHEMA,
        "field_id": FIELD_ID,
        "target": dict(target),
        "claim_boundary": (
            "This is only a Windows native executable long-packet transport probe. It does not claim "
            "detector quality, product security, API coverage, TP/FP/FN, release approval, or supervisor availability."
        ),
        "review_questions": [
            "Is the stated scope limited to a raw-free Windows native-executable transport probe without broader product claims?"
        ],
        "review_scope": {
            "claude_direct_files": [direct_file],
            "grok": "sanitized-packet",
            "glm": "sanitized-packet",
        },
        "transport_contract": {
            "required_native_suffix": ".exe",
            "shim_command_line_limit": SHIM_COMMAND_LINE_LIMIT,
            "native_command_line_limit": NATIVE_COMMAND_LINE_LIMIT,
            "raw_provider_output_persisted": False,
        },
        # This inert field makes the normal reviewer prompt exceed cmd.exe's documented 8,191-character boundary.
        "inert_transport_padding": "x" * padding_bytes,
        "raw_returned": False,
    }


def _terminal_summary(terminal: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "verdict": terminal["verdict"],
        "blocker_count": terminal["blocker_count"],
        "nonblocking_count": terminal["nonblocking_count"],
        "claim_boundary_confirmed": terminal["claim_boundary_confirmed"],
        "blocker_codes": terminal["blocker_codes"],
        "nonblocking_codes": terminal["nonblocking_codes"],
    }


def _blocked_lane(
    provider: str,
    *,
    command_line_char_count: int | None,
    executable_name: str | None,
    reason: str,
    exit_code: int | None,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "model": REQUIRED_MODELS[provider],
        "status": "BLOCKED",
        "transport_status": reason,
        "resolved_executable_name": executable_name,
        "resolved_executable_is_native": False,
        "command_line_char_count": command_line_char_count,
        "exit_code": exit_code,
        "terminal": None,
        "claude_direct_file_attested": False,
        "raw_returned": False,
    }


def _probe_lane(
    provider: str,
    *,
    executables: Mapping[str, str],
    packet: Mapping[str, Any],
    direct_file: str,
    repo_root: Path,
    output_dir: Path,
    timeout_seconds: int,
    runner: Runner,
) -> dict[str, Any]:
    command = review._provider_command(
        provider,
        executables=executables,
        packet=packet,
        direct_files=[direct_file],
        terminal_schema=review._terminal_schema(),
        output_dir=output_dir,
        timeout_seconds=timeout_seconds,
    )
    command_line_char_count = len(subprocess.list2cmdline(command))
    executable = Path(command[0])
    executable_name = executable.name
    native = executable.suffix.lower() == ".exe"
    if not native:
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason="native_executable_required",
            exit_code=None,
        )
    if command_line_char_count <= SHIM_COMMAND_LINE_LIMIT:
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason="long_packet_boundary_not_reached",
            exit_code=None,
        )
    if command_line_char_count >= NATIVE_COMMAND_LINE_LIMIT:
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason="native_command_line_limit_exceeded",
            exit_code=None,
        )
    try:
        completed = runner(
            command,
            cwd=repo_root if provider in {"claude", "grok"} else output_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason="timeout",
            exit_code=None,
        )
    except OSError:
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason="provider_error",
            exit_code=None,
        )
    if completed.returncode != 0:
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason="provider_exit",
            exit_code=completed.returncode,
        )
    terminal, reason, read_paths = review._parse_terminal_with_read_paths(provider, completed.stdout)
    if terminal is None or terminal["verdict"] == "BLOCKED":
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason=f"invalid_terminal_{reason}",
            exit_code=completed.returncode,
        )
    direct_attested = provider != "claude" or review._matched_direct_files(
        read_paths,
        repo_root=repo_root,
        direct_files=[direct_file],
    )
    if not direct_attested:
        return _blocked_lane(
            provider,
            command_line_char_count=command_line_char_count,
            executable_name=executable_name,
            reason="direct_file_tool_attestation_missing",
            exit_code=completed.returncode,
        )
    return {
        "provider": provider,
        "model": REQUIRED_MODELS[provider],
        "status": "GO" if terminal["verdict"] == "GO" else "HOLD",
        "transport_status": "ok" if terminal["verdict"] == "GO" else "reviewer_hold",
        "resolved_executable_name": executable_name,
        "resolved_executable_is_native": True,
        "command_line_char_count": command_line_char_count,
        "exit_code": completed.returncode,
        "terminal": _terminal_summary(terminal),
        "claude_direct_file_attested": direct_attested if provider == "claude" else False,
        "raw_returned": False,
    }


def _failure_reasons(lanes: Sequence[Mapping[str, Any]], *, target_unchanged: bool) -> list[str]:
    reasons: list[str] = []
    if not target_unchanged:
        reasons.append("target_changed_during_probe")
    for lane in lanes:
        provider = str(lane["provider"])
        if lane["status"] != "GO":
            reasons.append(f"lane_not_go:{provider}")
        if lane["resolved_executable_is_native"] is not True:
            reasons.append(f"native_executable_missing:{provider}")
        count = lane["command_line_char_count"]
        if not isinstance(count, int) or count <= SHIM_COMMAND_LINE_LIMIT:
            reasons.append(f"long_packet_boundary_missing:{provider}")
        if isinstance(count, int) and count >= NATIVE_COMMAND_LINE_LIMIT:
            reasons.append(f"native_command_line_limit_exceeded:{provider}")
        if provider == "claude" and lane["claude_direct_file_attested"] is not True:
            reasons.append("claude_direct_file_attestation_missing")
    return sorted(set(reasons))


def run_transport_probe(
    *,
    repo_root: Path,
    output: Path,
    direct_file: str,
    executables: Mapping[str, str],
    padding_bytes: int = DEFAULT_PADDING_BYTES,
    timeout_seconds: int = 600,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    if output.exists() or output.is_symlink() or _is_within(output, root):
        raise ValueError("transport probe output must be new and outside the repository")
    if not set(REQUIRED_MODELS).issubset(executables):
        raise ValueError("transport probe executable mapping is invalid")
    if timeout_seconds < 1 or timeout_seconds > 1200:
        raise ValueError("transport probe timeout is invalid")
    direct_path = _direct_file(root, direct_file)
    target = _capture_target(root)
    packet = _packet(target=target, direct_file=direct_path, padding_bytes=padding_bytes)
    packet_bytes = canonical_json_bytes(packet)
    if len(packet_bytes) <= SHIM_COMMAND_LINE_LIMIT:
        raise ValueError("transport probe packet does not cross the shim boundary")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(exist_ok=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(REQUIRED_MODELS)) as pool:
        futures = {
            provider: pool.submit(
                _probe_lane,
                provider,
                executables=executables,
                packet=packet,
                direct_file=direct_path,
                repo_root=root,
                output_dir=output,
                timeout_seconds=timeout_seconds,
                runner=runner,
            )
            for provider in REQUIRED_MODELS
        }
        lanes = [futures[provider].result() for provider in REQUIRED_MODELS]
    target_unchanged = _capture_target(root) == target
    failure_reasons = _failure_reasons(lanes, target_unchanged=target_unchanged)
    receipt = {
        "schema": SCHEMA,
        "field_id": FIELD_ID,
        "target": target,
        "packet_schema": PACKET_SCHEMA,
        "packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "packet_utf8_bytes": len(packet_bytes),
        "direct_file": direct_path,
        "padding_bytes": padding_bytes,
        "shim_command_line_limit": SHIM_COMMAND_LINE_LIMIT,
        "native_command_line_limit": NATIVE_COMMAND_LINE_LIMIT,
        "lanes": lanes,
        "target_unchanged_after_probe": target_unchanged,
        "status": "FIX" if not failure_reasons else "HOLD",
        "failure_reasons": failure_reasons,
        "authority": {
            "may_mark_native_transport_fix": not failure_reasons,
            "may_mark_product_or_release_fix": False,
            "may_affect_detector_quality": False,
            "may_affect_tp_fp_fn": False,
        },
        "raw_returned": False,
    }
    _write_canonical_new(output / "transport-probe.json", receipt)
    _write_canonical_new(output / "transport-packet.json", packet)
    return receipt


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Probe native Windows supervisor transport with a raw-free packet beyond the cmd.exe boundary."
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--direct-file", default="scripts/supervisor_executable_resolution.py")
    parser.add_argument("--padding-bytes", type=int, default=DEFAULT_PADDING_BYTES)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--claude-exe", default=os.environ.get("K_GUARD_CLAUDE_EXE", "claude"))
    parser.add_argument("--grok-exe", default=os.environ.get("K_GUARD_GROK_EXE", "grok"))
    args = parser.parse_args(argv)
    receipt = run_transport_probe(
        repo_root=args.repo_root,
        output=args.output.expanduser().resolve(strict=False),
        direct_file=args.direct_file,
        executables={"claude": args.claude_exe, "grok": args.grok_exe},
        padding_bytes=args.padding_bytes,
        timeout_seconds=args.timeout_seconds,
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "failure_reasons": receipt["failure_reasons"],
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
