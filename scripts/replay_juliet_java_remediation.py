from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from run_juliet_java_holdout import (  # noqa: E402
    ARCHIVE_SHA256,
    REPORT_SCHEMA,
    WORKER_SCHEMA,
    _read_json,
    _score,
    _sha256,
)


REPLAY_SCHEMA = "k_guard_juliet_java_remediation_replay.v1"


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "git command failed")
    return completed.stdout.strip()


def build_result(
    first_result: dict[str, Any],
    worker_payloads: list[dict[str, Any]],
    worker_hashes: list[str],
    *,
    execution_revision: str,
    first_result_sha256: str,
) -> dict[str, Any]:
    if first_result.get("schema") != REPORT_SCHEMA:
        raise ValueError("first Juliet holdout result schema is invalid")
    previous_metrics = first_result.get("metrics") if isinstance(first_result.get("metrics"), dict) else {}
    if int(previous_metrics.get("false_negative", 0) or 0) <= 0:
        raise ValueError("remediation replay requires a retained first result with false negatives")
    if len(worker_payloads) != 2 or any(payload.get("schema") != WORKER_SCHEMA for payload in worker_payloads):
        raise ValueError("two valid fresh-process worker payloads are required")
    if len(worker_hashes) != 2:
        raise ValueError("two worker hashes are required")
    exact_repeat = worker_hashes[0] == worker_hashes[1]
    first_units = worker_payloads[0].get("units") if isinstance(worker_payloads[0].get("units"), list) else []
    second_units = worker_payloads[1].get("units") if isinstance(worker_payloads[1].get("units"), list) else []
    metrics, cases = _score(first_units)
    previous_cases = first_result.get("cases") if isinstance(first_result.get("cases"), list) else []
    remediated_variants = sorted(
        {
            str(case.get("flow_variant") or "")
            for case in previous_cases
            if isinstance(case, dict) and case.get("outcome") == "fn" and case.get("flow_variant")
        }
    )
    passed = (
        exact_repeat
        and first_units == second_units
        and not worker_payloads[0].get("errors")
        and not worker_payloads[1].get("errors")
        and metrics["false_negative"] == 0
        and metrics["false_positive"] == 0
        and metrics["total_units"] == int(previous_metrics.get("total_units", -1))
    )
    return {
        "schema": REPLAY_SCHEMA,
        "verdict": "pass" if passed else "hold",
        "passed": passed,
        "execution_revision": execution_revision,
        "source": first_result.get("source"),
        "archive_sha256": ARCHIVE_SHA256,
        "first_result": {
            "sha256": first_result_sha256,
            "scanner_revision": first_result.get("scanner_revision"),
            "metrics": previous_metrics,
        },
        "remediation": {
            "root_cause": "unknown Java control-flow sentinel changed identity during state cloning",
            "flow_variants": remediated_variants,
        },
        "runs": [
            {"run": index + 1, "worker_sha256": digest, "fresh_process": True}
            for index, digest in enumerate(worker_hashes)
        ],
        "exact_worker_repeat": exact_repeat,
        "metrics": metrics,
        "claim_boundary": {
            "same_public_corpus_reused_after_failure_analysis": True,
            "not_an_independent_holdout": True,
            "post_tuning_regression_evidence_only": True,
            "first_result_remains_the_independent_public_result": True,
            "not_full_product_language_or_rule_recall": True,
            "not_owned_or_partner_field_evidence": True,
            "does_not_grant_guardian_release_authority": True,
            "does_not_prove_award_readiness_by_itself": True,
        },
        "raw_returned": False,
    }


def run(first_result_path: Path, archive_path: Path, output_path: Path) -> dict[str, Any]:
    if _sha256(archive_path) != ARCHIVE_SHA256:
        raise RuntimeError("Juliet archive integrity check failed")
    first_result = _read_json(first_result_path)
    source = first_result.get("source") if isinstance(first_result.get("source"), dict) else {}
    if source.get("archive_sha256") != ARCHIVE_SHA256:
        raise RuntimeError("first result is not bound to the expected NIST archive")
    changed = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--quiet", "HEAD", "--", "src/k_guard_mcp/java_flow.py"],
        check=False,
    ).returncode
    if changed != 0:
        raise RuntimeError("commit the Java analyzer before generating remediation evidence")

    worker_payloads: list[dict[str, Any]] = []
    worker_hashes: list[str] = []
    worker_script = SCRIPTS / "run_juliet_java_holdout.py"
    with tempfile.TemporaryDirectory(prefix="kguard-juliet-remediation-") as temp_dir:
        for number in (1, 2):
            worker_path = Path(temp_dir) / f"worker-{number}.json"
            completed = subprocess.run(
                [sys.executable, str(worker_script), "--worker", "--archive", str(archive_path), "--output", str(worker_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if completed.returncode != 0 or not worker_path.is_file():
                raise RuntimeError(f"Juliet remediation worker {number} failed closed")
            payload = _read_json(worker_path)
            if payload.get("schema") != WORKER_SCHEMA or payload.get("errors"):
                raise RuntimeError(f"Juliet remediation worker {number} returned incomplete evidence")
            worker_payloads.append(payload)
            worker_hashes.append(_sha256(worker_path))

    result = build_result(
        first_result,
        worker_payloads,
        worker_hashes,
        execution_revision=_git("rev-parse", "HEAD"),
        first_result_sha256=_sha256(first_result_path),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay the retained NIST Juliet first-result failures after remediation.")
    parser.add_argument("--first-result", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.first_result.resolve(), args.archive.resolve(), args.output.resolve())
    print(json.dumps({"verdict": result["verdict"], "metrics": result["metrics"]}, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
