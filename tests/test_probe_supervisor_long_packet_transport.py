from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "probe_supervisor_long_packet_transport.py"
SPEC = importlib.util.spec_from_file_location("probe_supervisor_long_packet_transport_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

COMPARATOR_SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_supervisor_long_packet_transport_repeats.py"
COMPARATOR_SPEC = importlib.util.spec_from_file_location("compare_supervisor_long_packet_transport_test", COMPARATOR_SCRIPT)
assert COMPARATOR_SPEC is not None and COMPARATOR_SPEC.loader is not None
comparison = importlib.util.module_from_spec(COMPARATOR_SPEC)
COMPARATOR_SPEC.loader.exec_module(comparison)

REPOSITORY_ROOT = Path(__file__).parents[1].resolve()
DIRECT_FILE = "scripts/supervisor_executable_resolution.py"


def _terminal() -> dict[str, object]:
    return {
        "verdict": "GO",
        "blocker_count": 0,
        "nonblocking_count": 0,
        "claim_boundary_confirmed": True,
        "blocker_codes": [],
        "nonblocking_codes": [],
        "finding_summary": "transport-only scope confirmed",
    }


def _wrapped(provider: str) -> bytes:
    terminal = json.dumps(_terminal(), separators=(",", ":"))
    if provider == "claude":
        return "\n".join(
            (
                json.dumps(
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "id": "read-1",
                                    "name": "Read",
                                    "input": {"file_path": str((REPOSITORY_ROOT / DIRECT_FILE).resolve())},
                                }
                            ]
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {"type": "tool_result", "tool_use_id": "read-1", "content": "discarded"}
                            ]
                        },
                    }
                ),
                json.dumps({"type": "result", "is_error": False, "subtype": "success", "result": terminal}),
            )
        ).encode("utf-8")
    if provider == "grok":
        return json.dumps({"text": terminal}).encode("utf-8")
    return json.dumps({"type": "run_result", "text": terminal}).encode("utf-8")


def _runner(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
    provider = "claude" if "claude-opus-5" in command else "grok" if "grok-4.6" in command else "glm"
    return subprocess.CompletedProcess(command, 0, stdout=_wrapped(provider), stderr=b"")


def _run(tmp_path: Path, name: str) -> dict[str, object]:
    return probe.run_transport_probe(
        repo_root=REPOSITORY_ROOT,
        output=tmp_path / name,
        direct_file=DIRECT_FILE,
        executables={"claude": sys.executable, "grok": sys.executable},
        runner=_runner,
        timeout_seconds=30,
    )


def test_probe_uses_native_executables_and_crosses_cmd_boundary(tmp_path: Path) -> None:
    receipt = _run(tmp_path, "r1")

    assert receipt["status"] == "FIX"
    assert receipt["failure_reasons"] == []
    assert receipt["raw_returned"] is False
    assert receipt["packet_utf8_bytes"] > probe.SHIM_COMMAND_LINE_LIMIT
    lanes = {lane["provider"]: lane for lane in receipt["lanes"]}
    assert set(lanes) == {"claude", "grok"}
    assert all(lane["resolved_executable_is_native"] is True for lane in lanes.values())
    assert all(lane["command_line_char_count"] > probe.SHIM_COMMAND_LINE_LIMIT for lane in lanes.values())
    assert all(lane["command_line_char_count"] < probe.NATIVE_COMMAND_LINE_LIMIT for lane in lanes.values())
    assert lanes["claude"]["claude_direct_file_attested"] is True
    assert (tmp_path / "r1" / "transport-probe.json").is_file()
    assert (tmp_path / "r1" / "transport-packet.json").is_file()


def test_probe_fails_closed_when_a_shim_is_retained(monkeypatch, tmp_path: Path) -> None:
    original = probe.review.resolve_supervisor_executable

    def resolve(value: str, **kwargs: object) -> str:
        if kwargs.get("provider") == "grok":
            return "C:/tools/grok.cmd"
        return original(value, **kwargs)

    monkeypatch.setattr(probe.review, "resolve_supervisor_executable", resolve)
    receipt = _run(tmp_path, "shim")

    assert receipt["status"] == "HOLD"
    assert "lane_not_go:grok" in receipt["failure_reasons"]
    assert "native_executable_missing:grok" in receipt["failure_reasons"]


def test_repeat_comparator_requires_two_semantically_identical_fixed_runs(tmp_path: Path) -> None:
    _run(tmp_path, "r1")
    _run(tmp_path, "r2")

    result = comparison.compare_runs(tmp_path / "r1", tmp_path / "r2")

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["raw_returned"] is False


def test_comparator_rejects_a_tampered_fixed_receipt(tmp_path: Path) -> None:
    _run(tmp_path, "r1")
    _run(tmp_path, "r2")
    path = tmp_path / "r2" / "transport-probe.json"
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["lanes"][0]["resolved_executable_is_native"] = False
    path.write_bytes(probe.canonical_json_bytes(receipt))

    try:
        comparison.compare_runs(tmp_path / "r1", tmp_path / "r2")
    except ValueError as exc:
        assert "not fixed" in str(exc)
    else:
        raise AssertionError("tampered transport receipt was accepted")
