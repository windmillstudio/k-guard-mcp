from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from k_guard_mcp.supervisor_reviews import (  # noqa: E402
    REQUIRED_MODELS,
    SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
    canonical_json_bytes,
    evaluate_supervisor_review_receipts,
    sha256_bytes,
)


SCHEMA = "k_guard_supervisor_repeat_comparison.v1"
REQUIRED_FILES = {
    "receipts": "supervisor-receipts.json",
    "decision": "supervisor-decision.json",
    "manifest": "evidence-manifest.json",
    "packet": "review-packet.json",
}


def _load_canonical(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("repeat input file is invalid")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("repeat input is not canonical JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("repeat input is not canonical JSON")
    return value


def _load_run(run_dir: Path) -> dict[str, Any]:
    root = run_dir.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("repeat run directory is invalid")
    loaded = {label: _load_canonical(root / name) for label, name in REQUIRED_FILES.items()}
    bundle = loaded["receipts"]
    if bundle.get("schema") != SUPERVISOR_REVIEW_RECEIPTS_SCHEMA:
        raise ValueError("repeat comparison requires current supervisor receipt schema")
    evaluated = evaluate_supervisor_review_receipts(bundle)
    manifest = loaded["manifest"]
    packet = loaded["packet"]
    decision = loaded["decision"]
    if (
        manifest.get("raw_returned") is not False
        or packet.get("raw_returned") is not False
        or decision.get("raw_returned") is not False
        or sha256_bytes(manifest) != bundle.get("evidence_manifest_sha256")
        or sha256_bytes(packet) != bundle.get("review_packet_sha256")
        or manifest.get("target") != bundle.get("target")
        or packet.get("target") != bundle.get("target")
        or decision.get("target") != bundle.get("target")
        or decision.get("field_id") != bundle.get("field_id")
        or decision.get("evidence_manifest_sha256") != bundle.get("evidence_manifest_sha256")
        or decision.get("review_packet_sha256") != bundle.get("review_packet_sha256")
        or decision.get("verdicts") != evaluated.get("verdicts")
        or decision.get("preflight_passed") is not True
        or decision.get("target_unchanged_after_review") is not True
    ):
        raise ValueError("repeat run evidence binding is invalid")
    attestation = bundle.get("test_attestation")
    if not isinstance(attestation, dict) or (
        attestation.get("focused_passed") is not True
        or attestation.get("full_regression_passed") is not True
        or attestation.get("repeat_required") is not True
        or attestation.get("repeat_exact") is not False
        or attestation.get("raw_returned") is not False
    ):
        raise ValueError("repeat run must be an unpromoted baseline")
    receipts = bundle.get("receipts")
    if not isinstance(receipts, list) or any(receipt.get("verdict") != "GO" for receipt in receipts):
        raise ValueError("repeat run did not receive every required GO verdict")
    if any(
        receipt.get("nonblocking_count") != 1
        or receipt.get("nonblocking_codes") != ["REPEATABILITY_GAP"]
        for receipt in receipts
    ):
        raise ValueError("repeat baseline did not record the required nonblocking repeatability gap")
    if evaluated["verdicts"] != {provider: "GO" for provider in REQUIRED_MODELS}:
        raise ValueError("repeat run receipts are inconsistent")
    return loaded


def _semantic_projection(run: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    bundle = run["receipts"]
    return {
        "field_id": bundle["field_id"],
        "target": bundle["target"],
        "evidence_manifest_sha256": bundle["evidence_manifest_sha256"],
        "review_packet_sha256": bundle["review_packet_sha256"],
        "direct_file_count": bundle["direct_file_count"],
        "direct_file_set_sha256": bundle["direct_file_set_sha256"],
        "test_attestation": bundle["test_attestation"],
        "receipts": bundle["receipts"],
        "manifest_sha256": sha256_bytes(run["manifest"]),
        "packet_sha256": sha256_bytes(run["packet"]),
    }


def compare_runs(run_a: Path, run_b: Path) -> dict[str, Any]:
    first = _load_run(run_a)
    second = _load_run(run_b)
    first_projection = _semantic_projection(first)
    second_projection = _semantic_projection(second)
    first_fingerprint = sha256_bytes(first_projection)
    second_fingerprint = sha256_bytes(second_projection)
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "field_id": first_projection["field_id"],
        "target": first_projection["target"],
        "run_count": 2,
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_count_as_scorecard_achievement": repeat_exact,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "raw_returned": False,
    }


def write_comparison(output: Path, comparison: Mapping[str, Any]) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite repeat comparison evidence")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical_json_bytes(dict(comparison)))
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two raw-free, unpromoted supervisor review runs.")
    parser.add_argument("--run-a", type=Path, required=True)
    parser.add_argument("--run-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    comparison = compare_runs(args.run_a, args.run_b)
    write_comparison(args.output, comparison)
    print(
        json.dumps(
            {
                "field_id": comparison["field_id"],
                "repeat_exact": comparison["repeat_exact"],
                "status": comparison["status"],
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if comparison["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
