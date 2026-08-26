from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    import check_external_supervisor_health as health
except ModuleNotFoundError:
    from scripts import check_external_supervisor_health as health


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SCHEMA = "k_guard_external_supervisor_health_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _load_canonical(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("health receipt is invalid")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("health receipt is invalid") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("health receipt is not canonical")
    return value, hashlib.sha256(raw).hexdigest()


def _health_reasons(receipt: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    try:
        schema_lanes = health.lanes_for_schema(receipt.get("schema"))
    except ValueError:
        reasons.append("schema_invalid")
        schema_lanes = ()
    if receipt.get("raw_returned") is not False:
        reasons.append("raw_returned")
    if receipt.get("approval") is not False or receipt.get("review_receipt_eligible") is not False:
        reasons.append("claim_boundary_invalid")
    if receipt.get("expected_terminal_decision") != health.EXPECTED_TERMINAL_DECISION:
        reasons.append("terminal_contract_invalid")
    if receipt.get("all_required_lanes_healthy") is not True or receipt.get("overall_status") != "HEALTHY":
        reasons.append("health_unhealthy")
    lanes = receipt.get("lanes")
    expected_lanes = {lane["provider"]: lane for lane in schema_lanes}
    if not isinstance(lanes, list) or len(lanes) != len(expected_lanes):
        reasons.append("lane_set_invalid")
    else:
        observed = {lane.get("provider"): lane for lane in lanes if isinstance(lane, Mapping)}
        if set(observed) != set(expected_lanes):
            reasons.append("lane_set_invalid")
        else:
            for provider, expected in expected_lanes.items():
                lane = observed[provider]
                if (
                    lane.get("model") != expected["model"]
                    or lane.get("invocation_profile") != expected["invocation_profile"]
                    or lane.get("status") != "HEALTHY"
                    or lane.get("blocked_reason") is not None
                    or lane.get("exit_code") != 0
                    or lane.get("terminal_response_valid") is not True
                    or lane.get("raw_returned") is not False
                ):
                    reasons.append(f"lane_invalid:{provider}")
    try:
        fingerprint = health.health_measurement_fingerprint(receipt)
    except (TypeError, ValueError):
        reasons.append("fingerprint_invalid")
    else:
        if receipt.get("measurement_fingerprint_sha256") != fingerprint:
            reasons.append("fingerprint_invalid")
    return sorted(set(reasons))


def compare_runs(first_path: Path, second_path: Path) -> dict[str, Any]:
    first, first_sha256 = _load_canonical(first_path)
    second, second_sha256 = _load_canonical(second_path)
    first_reasons = _health_reasons(first)
    second_reasons = _health_reasons(second)
    first_fingerprint = first.get("measurement_fingerprint_sha256")
    second_fingerprint = second.get("measurement_fingerprint_sha256")
    reasons = [*(f"first:{reason}" for reason in first_reasons), *(f"second:{reason}" for reason in second_reasons)]
    if first_fingerprint != second_fingerprint:
        reasons.append("health_semantic_difference")
    repeat_exact = not reasons
    result = {
        "schema": SCHEMA,
        "first_receipt_sha256": first_sha256,
        "second_receipt_sha256": second_sha256,
        "first_measurement_fingerprint_sha256": first_fingerprint,
        "second_measurement_fingerprint_sha256": second_fingerprint,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "failure_reasons": sorted(reasons),
        "raw_returned": False,
    }
    result["semantic_fingerprint_sha256"] = sha256_bytes(
        {
            "schema": result["schema"],
            "first_measurement_fingerprint_sha256": first_fingerprint,
            "second_measurement_fingerprint_sha256": second_fingerprint,
            "repeat_exact": repeat_exact,
            "status": result["status"],
            "failure_reasons": result["failure_reasons"],
            "raw_returned": False,
        }
    )
    return result


def write_result(path: Path, result: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or _is_within(path, REPOSITORY_ROOT):
        raise ValueError("health comparison output must be new and outside the repository")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(result)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("health comparison output must be new and outside the repository") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two raw-free external supervisor health receipts.")
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = compare_runs(args.first, args.second)
    write_result(args.output.expanduser().resolve(strict=False), result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
