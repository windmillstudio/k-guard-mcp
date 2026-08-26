from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from capture_supervisor_target import capture_target
from seal_current_baseline import _load_canonical_receipt, validate_current_baseline

from k_guard_mcp.l1_benchmark import L1BenchmarkError, run_l1_baseline, write_l1_baseline_report


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return True
    return False


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the pinned full OWASP Java/Python L1 baseline twice without a release promotion."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--benchmark-java", type=Path, required=True)
    parser.add_argument("--benchmark-python", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    output_dir = args.output_dir.resolve()
    if output_dir.exists() or not _outside_repository(output_dir):
        raise L1BenchmarkError("l1_output_dir_must_be_new_and_external")
    if not _outside_repository(args.baseline_receipt):
        raise L1BenchmarkError("baseline_receipt_must_be_external")
    receipt = _load_canonical_receipt(args.baseline_receipt)
    validate_current_baseline(ROOT, receipt)
    target = capture_target(ROOT)
    report = run_l1_baseline(
        args.manifest,
        benchmark_java=args.benchmark_java,
        benchmark_python=args.benchmark_python,
        execution_binding={
            "baseline_receipt_sha256": receipt["receipt_sha256"],
            "target": target,
        },
    )
    if capture_target(ROOT) != target:
        raise L1BenchmarkError("scanner_target_changed_during_l1")
    output = output_dir / "l1-baseline-report.json"
    write_l1_baseline_report(report, output)
    aggregate = report.get("aggregate") or {}
    print(
        json.dumps(
            {
                "complete": report.get("complete") is True,
                "status": report.get("status"),
                "total_case_count": aggregate.get("official_denominator", {}).get("total_case_count", 0),
                "supported_case_count": aggregate.get("official_denominator", {}).get("supported_case_count", 0),
                "repeat_exact": report.get("repeat", {}).get("exact") is True,
                "output": str(output),
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if report.get("complete") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
