from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "k_guard_maven_osv_observe_repeat_comparison.v1"
SOURCE_SCHEMA = "k_guard_maven_osv_observe_ab.v1"


class ComparisonError(ValueError):
    pass


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_canonical(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComparisonError("repeat_report_invalid") from exc
    if not isinstance(payload, dict) or _canonical_bytes(payload) != raw:
        raise ComparisonError("repeat_report_not_canonical")
    return payload, _sha256(raw)


def _required_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ComparisonError(f"{label}_invalid")
    return value


def _required_bool(value: Any, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise ComparisonError(f"{label}_invalid")
    return value


def _run_projection(value: Any) -> dict[str, Any]:
    run = _required_mapping(value, label="run")
    projected: dict[str, Any] = {}
    for side in ("positive", "negative"):
        item = _required_mapping(run.get(side), label=f"{side}_run")
        matches = item.get("expected_cve_matches")
        if not isinstance(matches, list) or any(not isinstance(row, dict) for row in matches):
            raise ComparisonError("expected_cve_matches_invalid")
        for key in (
            "exit_code",
            "result_count",
            "package_count",
            "vulnerability_count",
            "expected_cve_match_count",
        ):
            if isinstance(item.get(key), bool) or not isinstance(item.get(key), int) or item[key] < 0:
                raise ComparisonError(f"{side}_{key}_invalid")
        projected[side] = {
            "exit_code": item["exit_code"],
            "result_count": item["result_count"],
            "package_count": item["package_count"],
            "vulnerability_count": item["vulnerability_count"],
            "expected_cve_match_count": item["expected_cve_match_count"],
            "expected_cve_matches": matches,
        }
    return projected


def _source_projection(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("schema") != SOURCE_SCHEMA:
        raise ComparisonError("source_schema_invalid")
    hypothesis = _required_mapping(report.get("hypothesis"), label="hypothesis")
    oracle = _required_mapping(report.get("oracle"), label="oracle")
    repeat = _required_mapping(report.get("repeat"), label="repeat")
    binding = _required_mapping(report.get("execution_binding"), label="execution_binding")
    engine = _required_mapping(report.get("engine"), label="engine")
    inputs = _required_mapping(report.get("inputs"), label="inputs")
    runs = report.get("runs")
    if report.get("complete") is not True or report.get("status") != "MEASURED_HOLD":
        raise ComparisonError("source_measurement_not_complete")
    if hypothesis.get("id") != "H5A" or hypothesis.get("stage") != "observe":
        raise ComparisonError("source_hypothesis_invalid")
    if (
        _required_bool(oracle.get("pair_admitted"), label="oracle_pair_admitted") is not True
        or _required_bool(repeat.get("semantic_exact"), label="internal_semantic_exact") is not True
        or not isinstance(runs, list)
        or len(runs) != 2
    ):
        raise ComparisonError("source_oracle_not_admitted")
    projections = [_run_projection(item) for item in runs]
    if not all(
        run["positive"]["expected_cve_match_count"] == 1
        and run["negative"]["expected_cve_match_count"] == 0
        for run in projections
    ):
        raise ComparisonError("source_oracle_projection_invalid")
    if hypothesis.get("warning_promotion_admitted") is not False or hypothesis.get("blocking_promotion_admitted") is not False:
        raise ComparisonError("source_promotion_boundary_invalid")
    return {
        "expected_cve": report.get("expected_cve"),
        "engine": engine,
        "inputs": inputs,
        "execution_binding": binding,
        "runs": projections,
    }


def _raw_output_projection(report: Mapping[str, Any]) -> list[dict[str, str]]:
    rows = report.get("runs")
    if not isinstance(rows, list):
        raise ComparisonError("runs_invalid")
    result: list[dict[str, str]] = []
    for run in rows:
        run_map = _required_mapping(run, label="run")
        positive = _required_mapping(run_map.get("positive"), label="positive_run")
        negative = _required_mapping(run_map.get("negative"), label="negative_run")
        positive_hash = positive.get("stdout_sha256")
        negative_hash = negative.get("stdout_sha256")
        if not isinstance(positive_hash, str) or not isinstance(negative_hash, str):
            raise ComparisonError("raw_output_hash_invalid")
        result.append({"positive_stdout_sha256": positive_hash, "negative_stdout_sha256": negative_hash})
    return result


def compare_reports(first: Mapping[str, Any], second: Mapping[str, Any], *, first_sha256: str, second_sha256: str) -> dict[str, Any]:
    first_projection = _source_projection(first)
    second_projection = _source_projection(second)
    semantic_exact = first_projection == second_projection
    raw_output_exact = _raw_output_projection(first) == _raw_output_projection(second)
    return {
        "schema": SCHEMA,
        "field_id": "H5A",
        "status": "FIX_NARROW_ORACLE_ONLY" if semantic_exact else "HOLD",
        "source_reports": [
            {"content_sha256": first_sha256, "raw_returned": False},
            {"content_sha256": second_sha256, "raw_returned": False},
        ],
        "repeat": {
            "semantic_exact": semantic_exact,
            "raw_osv_output_exact": raw_output_exact,
            "raw_output_variance_blocks_general_maven_sca_promotion": not raw_output_exact,
            "raw_returned": False,
        },
        "claim_boundary": {
            "narrow_machine_oracle_repeat_fixed": semantic_exact,
            "general_maven_sca_adapter_fixed": False,
            "guardian_policy_changed": False,
            "warning_promotion_admitted": False,
            "blocking_promotion_admitted": False,
            "release_gate_passed": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _write_new(path: Path, payload: Mapping[str, Any]) -> None:
    if not path.is_absolute():
        raise ComparisonError("output_path_must_be_absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ComparisonError("output_path_already_exists") from exc
    except OSError as exc:
        raise ComparisonError("output_path_unavailable") from exc
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(_canonical_bytes(dict(payload)))
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two H5A raw-free observer reports without promoting Maven SCA or Guardian."
    )
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        first, first_sha256 = _load_canonical(args.first)
        second, second_sha256 = _load_canonical(args.second)
        report = compare_reports(first, second, first_sha256=first_sha256, second_sha256=second_sha256)
        _write_new(args.output, report)
    except ComparisonError as exc:
        print(json.dumps({"status": "CONTROL_HOLD", "error": str(exc), "raw_returned": False}, sort_keys=True))
        return 3
    print(
        json.dumps(
            {
                "status": report["status"],
                "semantic_exact": report["repeat"]["semantic_exact"],
                "raw_osv_output_exact": report["repeat"]["raw_osv_output_exact"],
                "raw_returned": False,
            },
            sort_keys=True,
        )
    )
    return 0 if report["repeat"]["semantic_exact"] is True else 3


if __name__ == "__main__":
    raise SystemExit(main())
