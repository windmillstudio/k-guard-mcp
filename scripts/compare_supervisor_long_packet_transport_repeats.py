from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    import probe_supervisor_long_packet_transport as probe
except ModuleNotFoundError:
    from scripts import probe_supervisor_long_packet_transport as probe

from k_guard_mcp.supervisor_reviews import REQUIRED_MODELS, canonical_json_bytes, sha256_bytes


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SCHEMA = "k_guard_supervisor_long_packet_transport_repeat_comparison.v1"


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _load_canonical(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("transport probe receipt is invalid")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("transport probe receipt is invalid") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("transport probe receipt is not canonical")
    return value, hashlib.sha256(raw).hexdigest()


def _load_run(run_dir: Path) -> tuple[dict[str, Any], str]:
    root = run_dir.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("transport probe run is invalid")
    receipt, receipt_sha256 = _load_canonical(root / "transport-probe.json")
    packet, _ = _load_canonical(root / "transport-packet.json")
    if receipt.get("schema") != probe.SCHEMA or packet.get("schema") != probe.PACKET_SCHEMA:
        raise ValueError("transport probe schema is invalid")
    if receipt.get("raw_returned") is not False or packet.get("raw_returned") is not False:
        raise ValueError("transport probe must be raw-free")
    if canonical_json_bytes(packet).__len__() != receipt.get("packet_utf8_bytes"):
        raise ValueError("transport probe packet byte count is invalid")
    if hashlib.sha256(canonical_json_bytes(packet)).hexdigest() != receipt.get("packet_sha256"):
        raise ValueError("transport probe packet digest is invalid")
    if packet.get("target") != receipt.get("target") or packet.get("field_id") != receipt.get("field_id"):
        raise ValueError("transport probe packet binding is invalid")
    return receipt, receipt_sha256


def _semantic_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    lanes = receipt.get("lanes")
    if not isinstance(lanes, list) or len(lanes) != len(REQUIRED_MODELS):
        raise ValueError("transport probe lane set is invalid")
    by_provider = {lane.get("provider"): lane for lane in lanes if isinstance(lane, dict)}
    if set(by_provider) != set(REQUIRED_MODELS):
        raise ValueError("transport probe lane set is invalid")
    for provider in REQUIRED_MODELS:
        lane = by_provider[provider]
        if (
            lane.get("model") != REQUIRED_MODELS[provider]
            or lane.get("status") != "GO"
            or lane.get("transport_status") != "ok"
            or lane.get("resolved_executable_is_native") is not True
            or not isinstance(lane.get("command_line_char_count"), int)
            or lane["command_line_char_count"] <= probe.SHIM_COMMAND_LINE_LIMIT
            or lane["command_line_char_count"] >= probe.NATIVE_COMMAND_LINE_LIMIT
            or lane.get("exit_code") != 0
            or lane.get("raw_returned") is not False
        ):
            raise ValueError(f"transport probe lane is not fixed: {provider}")
        terminal = lane.get("terminal")
        if not isinstance(terminal, dict) or terminal.get("verdict") != "GO":
            raise ValueError(f"transport probe terminal is invalid: {provider}")
    if by_provider["claude"].get("claude_direct_file_attested") is not True:
        raise ValueError("transport probe Claude direct file attestation is missing")
    if (
        receipt.get("status") != "FIX"
        or receipt.get("failure_reasons") != []
        or receipt.get("target_unchanged_after_probe") is not True
        or receipt.get("raw_returned") is not False
        or receipt.get("authority", {}).get("may_mark_native_transport_fix") is not True
        or receipt.get("authority", {}).get("may_mark_product_or_release_fix") is not False
    ):
        raise ValueError("transport probe receipt is not a narrow fixed result")
    return {
        "field_id": receipt.get("field_id"),
        "target": receipt.get("target"),
        "packet_schema": receipt.get("packet_schema"),
        "packet_sha256": receipt.get("packet_sha256"),
        "packet_utf8_bytes": receipt.get("packet_utf8_bytes"),
        "direct_file": receipt.get("direct_file"),
        "padding_bytes": receipt.get("padding_bytes"),
        "shim_command_line_limit": receipt.get("shim_command_line_limit"),
        "native_command_line_limit": receipt.get("native_command_line_limit"),
        "lanes": [by_provider[provider] for provider in REQUIRED_MODELS],
        "raw_returned": False,
    }


def compare_runs(first_dir: Path, second_dir: Path) -> dict[str, Any]:
    first, first_sha256 = _load_run(first_dir)
    second, second_sha256 = _load_run(second_dir)
    first_projection = _semantic_projection(first)
    second_projection = _semantic_projection(second)
    first_fingerprint = sha256_bytes(first_projection)
    second_fingerprint = sha256_bytes(second_projection)
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "field_id": first_projection["field_id"],
        "target": first_projection["target"],
        "first_receipt_sha256": first_sha256,
        "second_receipt_sha256": second_sha256,
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_native_transport_fix": repeat_exact,
            "may_mark_product_or_release_fix": False,
            "may_affect_detector_quality": False,
            "may_affect_tp_fp_fn": False,
        },
        "raw_returned": False,
    }


def write_comparison(path: Path, result: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or _is_within(path, REPOSITORY_ROOT):
        raise ValueError("transport repeat comparison output must be new and outside the repository")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(result)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("transport repeat comparison output must be new and outside the repository") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two native long-packet supervisor transport probes.")
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = compare_runs(args.first, args.second)
    write_comparison(args.output.expanduser().resolve(strict=False), result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
